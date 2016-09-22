### Import des librairies
from struct import unpack
from binascii import hexlify
import hmac
import hashlib
import sys
import argparse

### def getDerivationKey(str(pwd), bytes(sel))
### Cette fonction retourne la clé de dérivation à partir du pwd et du sel
def getDerivationKey(pwd, sel):
    return hashlib.pbkdf2_hmac('sha1', bytes(pwd, encoding='utf-8'), sel, 1000, 66)

def dicCompare(d1, d2):
    d1_keys = set(d1.keys())
    d2_keys = set(d2.keys())
    intersect_keys = d1_keys.intersection(d2_keys)
    added = d1_keys - d2_keys
    removed = d2_keys - d1_keys
    modified = {o: (d1[o], d2[o]) for o in intersect_keys if d1[o] != d2[o]}
    same = set(o for o in intersect_keys if d1[o] == d2[o])
    return added, removed, modified, same

def dicIntegrity(flag, method, modTime, modDate, CRC32, compressedSize, uncompressedSize, filenameLen):
    dicTemplateIntegrity = { 'flag': flag, 'mode': method, 'mod_time': modTime, 'mod_date': modDate,
                             'crc32': CRC32, 'compressed_size': compressedSize,
                             'uncompressed_size': uncompressedSize, 'filename_length': filenameLen
                             }
    return dicTemplateIntegrity

####################################################################
### Local File Header ##############################################
####################################################################
class localFileHeader:
    def __init__(self, data, offset, pwd):
        #self.dicLocalFileHeader = []
        self.offset = offset
        self.password = pwd
        self.header = data[offset:offset+4]
        self.version = data[offset+4:offset+6]
        self.flag = data[offset+6:offset+8]
        self.method = unpack('=h', data[offset+8:offset+10])[0]
        self.modTime = unpack('cc', data[offset+10:offset+12])[0]
        self.modDate = unpack('cc', data[offset+12:offset+14])[0]
        self.CRC32 = unpack('cccc', data[offset+14:offset+18])[0]
        self.compressedSize = unpack('=i', data[offset+18:offset+22])[0]
        self.uncompressedSize = unpack('=i', data[offset+22:offset+26])[0]
        self.filenameLen = unpack('=h', data[offset+26:offset+28])[0]
        self.extraLen = unpack('=h', data[offset+28:offset+30])[0]
        self.filename = unpack('%ds' % self.filenameLen, data[offset+30:offset+30+self.filenameLen])[0].decode('utf-8')
        self.extra = data[offset+30+self.filenameLen:offset+30+self.filenameLen+self.extraLen]
        self.length = 30+self.filenameLen+self.extraLen+self.compressedSize
        # AES Header
        if self.method == 99:
            start = offset+30+self.filenameLen
            self.aesHeader = data[start:start+2]
            self.aesDataSize = unpack('=h', data[start+2:start+4])[0]
            self.aesVendor = unpack('=h', data[start+4:start+6])[0]
            self.aesVendorID = unpack('=h', data[start+6:start+8])[0]
            self.aesStrength = unpack('>h', b'\x00'+data[start+8:start+9])[0]
            self.aesMethod = unpack('=h', data[start+9:start+11])[0]
            # Encrypted file storage format
            self.encFile = data[start+11:self.offset+self.length]
            self.aesSalt = data[start+11:start+11+self.getSaltSize(self.aesStrength)]
            self.aesPwdVerifValue = data[start+11+self.getSaltSize(self.aesStrength):start+11+self.getSaltSize(self.aesStrength)+2]
            self.aesEncryptedData = data[start+11+self.getSaltSize(self.aesStrength)+2:self.offset+self.length-10]
            self.aesAuthCode = data[self.offset+self.length-10:self.offset+self.length]
            # AES verifications
            self.derivationKey = getDerivationKey(self.password, self.aesSalt)
            self.pwdVerifCodeDK = self.derivationKey[-2:]
            self.encryptionKey = self.derivationKey[:32]
            self.authenticationKey = self.derivationKey[32:-2]
            # Add values in dictionary for check header intrigity with central directory header
            # dicLocalFileHeader[self.filename] = dicIntegrity(self.flag, self.method, self.modTime, self.modDate, self.CRC32, self.compressedSize, self.uncompressedSize, self.filenameLen)
        return

    def getCryptMethod(self, method):
        dic = {
            0: 'No compression',
            1: 'Shrunk',
            2: 'Reduced with compression factor 1',
            3: 'Reduced with compression factor 2',
            4: 'Reduced with compression factor 3',
            5: 'Reduced with compression factor 4',
            6: 'Imploded',
            7: 'Reserved',
            8: 'Deflated',
            9: 'Enhanced deflated',
            10: 'PKWare DCL imploded',
            11: 'Reserved',
            12: 'Compressed using BZIP2',
            13: 'Reserved',
            14: 'LZMA',
            15: 'Reserved',
            16: 'Reserved',
            17: 'Reserved',
            18: 'Compressed using IBM TERSE',
            19: 'IBM LZ77 z',
            98: 'PPMd version I, Rev 1 ',
            99: 'AES'
        }
        return dic.get(method, 'UNKNOWN')
    
    def getSaltSize(self, strength):
        dic = {1: 8,
               2: 12,
               3: 16
               }
        return dic.get(strength, -1)
    
    def getCryptStrength(self, strength):
        dic = {1: '128',
               2: '192',
               3: '256'
               }
        return dic.get(strength, 'UNKNOWN')

    def getAuthCode(self):
        self.hmacAuthCode = hmac.new(self.authenticationKey, self.aesEncryptedData, hashlib.sha1).digest()[:10]
        return self.hmacAuthCode
    
    def getInfos(self):
        print('--- INFORMATIONS')
        print('    Nom du fichier :', self.filename)
        print('    Taille Compressée :', self.compressedSize)
        print('    Taille Decompressée :', self.uncompressedSize)
        print('    Méthode de compression :', self.getCryptMethod(self.method))
        if self.method == 99:
            self.getAESInfos()
            self.checkAESIntegrity()
        print('\n\n')
        return 0
    
    def getAESInfos(self):
        validAESHeader = b'\x01\x99'
        valid = self.aesHeader == validAESHeader
        print('    --- HEADER AES :', valid)
        print('        Taille de la clé :', self.getCryptStrength(self.aesStrength), 'bit')
        print('        Méthode :', self.getCryptMethod(self.aesMethod))
        print('        Debut des données chiffrées :', self.offset+30+self.filenameLen+11+self.getSaltSize(self.aesStrength)+2)
        print('        Fin des données chiffrées :', self.offset+self.length-10)
        print('        Salt ( Size:', len(self.aesSalt), ') : ', self.aesSalt)
        print('        Password verification :', self.aesPwdVerifValue)
        print('        Authentification code :', self.aesAuthCode)
        return 0

    def checkAESIntegrity(self):
        print("    --- INTEGRITE AES :")
        print('        Password verification :', self.pwdVerifCodeDK)
        print('        Authentification code :', self.getAuthCode())
        print('        Password verification integrity :', self.aesPwdVerifValue == self.pwdVerifCodeDK, )
        print('        Authentification code integrity :', self.aesAuthCode == self.getAuthCode())
        return 0

#####################################################################
### Central Directory Header ########################################
#####################################################################
class centralDirectoryHeader:
    def __init__(self, data, offset):
        start = offset
        self.signature = data[start:start+4]
        if self.signature != b'PK\x01\x02':
            print('Central Directory non valide !')
            exit(1)
        self.version = data[start+4:start+6]
        self.versionNeeded = data[start+6:start+8]
        self.flags = data[start+8:start+10]
        self.method = data[start+10:start+12]
        self.modTime = data[start+12:start+14]
        self.modDate = data[start+14:start+16]
        return
    
#####################################################################
### File ############################################################
#####################################################################
class File:
    def __init__(self, data, pwd):
        print('Creation du fichier ...')
        self.headers = []
        self.offset = 0
        self.compressedSize = 0
        self.size = 0
        self.data = data
        self.password = pwd
        print('Recherche des headers ...')
        validSign = b'PK\x03\x04'
        nbHeaders = 0
        while self.data[self.offset:self.offset+4] == validSign:
            self.headers.append(localFileHeader(self.data, self.offset, self.password))
            self.offset += self.headers[nbHeaders].length
            nbHeaders += 1
        print('Récupération du Central Directory Header ...')
        self.centralDir = centralDirectoryHeader(self.data, self.headers[nbHeaders-1].offset+self.headers[nbHeaders-1].length)
        print('Nombre de headers trouvé(s) :', nbHeaders)
        return

    def getHeadersInfos(self):
        totalUncompressedSizeLocalFileHeader = 0
        for h in self.headers:
            h.getInfos()
            totalUncompressedSizeLocalFileHeader += h.uncompressedSize
        print('--- Taille totale décompressée :', totalUncompressedSizeLocalFileHeader)
        return 0
    
#####################################################################
### MAIN ############################################################
#####################################################################
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('zip', help='zip file to analyze')
    parser.add_argument('-v', '--verbose', action='store_true', default=False, help='Print all headers')
    parser.add_argument('-p', '--password', type=str, help='Set password for decrypt zip file')
    args = parser.parse_args()
    dargs = vars(parser.parse_args())

    zip_name = args.zip
    verbose = dargs['verbose']
    password = str(dargs['password'])
        
    try:
        f = open(zip_name, 'rb')
    except IOError as e:
        print(e.strerror)
        exit(e.errno)
        
    fic = File(f.read(), password)
    f.close()
    fic.getHeadersInfos()

    '''
    # Integrity informations
    added_filename, removed_filename, modified_filename, same_filename = dict_compare(check_file_header_dict, check_cent_dir_header_dict)
    if total_files == len(same_filename):
        integrity = True
    else:
        integrity = False
    print('Integrity between "File Headers" and "Central Directory Headers" :', integrity)
    if not integrity:
        print('\t', len(added_filename), 'ajouté(s),', len(removed_filename), 'supprimé(s),', len(modified_filename),
              'modifié(s) et', len(same_filename), 'identique(s),')
        print('\t\t Added:', ' , '.join(added_filename), '\n\t\t Removed:', ' , '.join(removed_filename))
        for file in modified_filename:
            added_value, removed_value, modified_value, same_value = dict_compare(check_file_header_dict[file], check_cent_dir_header_dict[file])
            print('\t\t Modified:', file, modified_value)
    '''
