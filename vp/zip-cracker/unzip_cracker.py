import zipfile
from threading import Thread
import optparse



def extractFile(zFile, password, action='EXIT'):
    try:
        zFile.extractall(pwd=bytes(password, "utf-8"))
        print(f"[+] Password Found: {password}")
        if action == 'EXIT':
            exit(0)
        return password
    except Exception as e:
        return

def main():
    parser = optparse.OptionParser("usage%prog -f <zipfile> -d <dictionaryfile>")
    parser.add_option('-f', dest='zname', type='string', help='specify zip file')
    parser.add_option('-d', dest='dname', type='string', help='specify dictionary file')
    (options, args) = parser.parse_args()
    if (options.zname is None) | (options.dname is None):
        print(parser.usage)
        exit(0)

    zname = options.zname
    dname = options.dname

    zFile = zipfile.ZipFile(zname)
    passfile = open(dname, "r")
    for line in passfile:
        password = line.strip('\n')
        t = Thread(target=extractFile, args=(zFile, password))
        t.start()
    
if __name__ == "__main__":
    main()
