# python3
# (c) Italo Almeida 2022, GPL-3.0 License
# FINAL REALME X (RMX1901) UNBRICK TOOL - A.05 / ANDROID 9 SUPPORT
import os
import sys
import time
import shutil
import hashlib
import tempfile
import subprocess
import xml.etree.ElementTree as ET
from Cryptodome.Cipher import AES
from Cryptodome.Hash import MD5
from binascii import hexlify
from struct import unpack

os.system("")
cpcount = 0
invalidsuper = False
fatalerror = ""

def byebye():
    input("\nPress Enter to exit...")
    exit(0)
    
def cleanprevious(x):
    for i in range(x):
        sys.stdout.write("\033[A")
        sys.stdout.write("\033[K")

def printc(msg):
    global cpcount
    cpcount += 1 + msg.count("\n")
    print(msg)

def ROR(x, n, bits = 32):
    mask = (2**n) - 1
    mask_bits = x & mask
    return (x >> n) | (mask_bits << (bits - n))

def ROL(x, n, bits = 32):
    return ROR(x, bits - n, bits)

def bytestolow(data):
    h = MD5.new()
    h.update(data)
    shash = h.digest()
    return hexlify(shash).lower()[0:16]

def deobfuscate(data,mask):
    ret=bytearray()
    for i in range(0, len(data)):
        v = ROL((data[i] ^ mask[i]), 4, 8)
        ret.append(v)
    return ret

def aes_cfb(data,key,iv):
    ctx = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128)
    return ctx.decrypt(data)

def generatekey(filename):
    keys = [
        ["V1.4.17/1.4.27", "27827963787265EF89D126B69A495A21", "82C50203285A2CE7D8C3E198383CE94C", "422DD5399181E223813CD8ECDF2E4D72"],
        ["V1.6.17", "E11AA7BB558A436A8375FD15DDD4651F", "77DDF6A0696841F6B74782C097835169", "A739742384A44E8BA45207AD5C3700EA"],
        ["V1.5.13", "67657963787565E837D226B69A495D21", "F6C50203515A2CE7D8C3E1F938B7E94C", "42F2D5399137E2B2813CD8ECDF2F4D72"],
        ["V1.6.6/1.6.9/1.6.17/1.6.24/1.6.26/1.7.6", "3C2D518D9BF2E4279DC758CD535147C3", "87C74A29709AC1BF2382276C4E8DF232", "598D92E967265E9BCABE2469FE4A915E"],
        ["V1.7.2", "8FB8FB261930260BE945B841AEFA9FD4", "E529E82B28F5A2F8831D860AE39E425D", "8A09DA60ED36F125D64709973372C1CF"],
        ["V2.0.3", "E8AE288C0192C54BF10C5707E9C4705B", "D64FC385DCD52A3C9B5FBA8650F92EDA", "79051FD8D8B6297E2E4559E997F63B7F"]
    ]

    for dkey in keys:
        mc = bytearray.fromhex(dkey[1])
        userkey=bytearray.fromhex(dkey[2])
        ivec=bytearray.fromhex(dkey[3])

        key=deobfuscate(userkey,mc)
        iv=deobfuscate(ivec,mc)

        key=bytestolow(key)
        iv=bytestolow(iv)
        pagesize,data=extract_xml(filename,key,iv)
        if pagesize!=0:
            return pagesize,key,iv,data
    return 0,None,None,None

def extract_xml(filename,key,iv):
    filesize=os.stat(filename).st_size
    with open(filename,'rb') as rf:
        pagesize = 0
        for x in [0x200, 0x1000]:
            rf.seek(filesize-x+0x10)
            if unpack("<I",rf.read(4))[0]==0x7CEF:
                pagesize = x
                break 
        if pagesize == 0:
            return 0,""
            
        xmloffset=filesize-pagesize
        rf.seek(xmloffset+0x14)
        offset=unpack("<I",rf.read(4))[0]*pagesize
        length=unpack("<I",rf.read(4))[0]
        if length<200:
            length=xmloffset-offset-0x57
        rf.seek(offset)
        data=rf.read(length)
        dec=aes_cfb(data,key,iv)

        if b"<?xml" in dec:
            return pagesize,dec
        else:
            return 0,""

def copysub(rf,wf,start,length):
    rf.seek(start)
    rlen=0
    while length > 0:
        if length < 0x100000:
            size = length
        else:
            size = 0x100000
        data = rf.read(size)
        wf.write(data)
        rlen+=len(data)
        length -= size
    return rlen

def copy(filename, path, wfilename, start, length, checksums):
    print(f"\nEXTRACTING: {os.path.splitext(wfilename)[0]}")
    with open(filename, 'rb') as rf:
        with open(os.path.join(path, wfilename), 'wb') as wf:
            rf.seek(start)
            data=rf.read(length)
            wf.write(data)

    checkhashfile(path, wfilename, checksums)

def decryptfile(issuper, key, iv, filename, path, wfilename, start, length, rlength, checksums, decryptsize):
    if not issuper:
        print(f"\nEXTRACTING: {os.path.splitext(wfilename)[0]}")
    if rlength==length:
        tlen=length
        length=(length//0x4*0x4)
        if tlen%0x4!=0:
            length+=0x4

    with open(filename, 'rb') as rf:
        with open(os.path.join(path, wfilename), 'wb') as wf:
            rf.seek(start)
            size=decryptsize
            if rlength<decryptsize:
                size=rlength
            data=rf.read(size)
            if size%4:
                data+=(4-(size%4))*b'\x00'
                
            outp = aes_cfb(data, key, iv)
            wf.write(outp[:size])

            if rlength > decryptsize:
                copysub(rf, wf, start + size, rlength-size)

    checkhashfile(path, wfilename, checksums)

def checkhashfile(path, wfilename, checksums):
    global invalidsuper
    sha256sum = checksums[0]
    md5sum = checksums[1]
    filepath = os.path.join(path, wfilename)
    with open(filepath,"rb") as rf:
        size = os.stat(filepath).st_size
        md5 = hashlib.md5(rf.read(0x40000))
        sha256bad=False
        md5bad=False
        if sha256sum != "":
            for x in [0x40000, size]:
                rf.seek(0)
                sha256 = hashlib.sha256(rf.read(x))
                if sha256sum != sha256.hexdigest():
                    sha256bad=True
                else:
                    sha256bad=False
                    break
        if md5sum != "":
            if md5sum != md5.hexdigest():
                md5bad=True
        if wfilename in ["super0.img", "super1.img", "super2.img"]:
            if sha256bad and md5bad:
                invalidsuper = True
            return
        if sha256bad and md5bad:
            print(f"EXTRACT ERROR: Error on hashes. OFP {os.path.splitext(wfilename)[0]} partition might be broken!")
        else:
            flashpartition(os.path.splitext(wfilename)[0], filepath)
    os.remove(filepath)
    
def flashpartition(partition, file):
    global fatalerror
    print(f"FLASHING: {partition}...", end=" ", flush=True)
    try:
        flashreturn = str(subprocess.check_output(["fastboot", "flash", partition, file], stderr=subprocess.STDOUT))
        print("SUCCESS")
    except subprocess.CalledProcessError as e:
        flashreturn = str(e.output)
        if "FAILED (remote: Flashing is not allowed for Critical Partitions" in flashreturn:
            print("SKIPPED (Critical Partition)")
        elif "unknown partition" in flashreturn.lower() or "not found" in flashreturn.lower():
            print("SKIPPED (Partition not found)")
        elif "FAILED" in flashreturn:
            print("FAILED")
    if "read failed (Too many links)" in flashreturn:
        fatalerror = "Use another USB port or another cable, and try flash again!"

def decryptitem(item, pagesize):
    sha256sum=""
    md5sum=""
    wfilename=""
    start=-1
    rlength=0
    decryptsize=0x40000
    if "Path" in item.attrib:
        wfilename = item.attrib["Path"]
    elif "filename" in item.attrib:
        wfilename = item.attrib["filename"]
    if "sha256" in item.attrib:
        sha256sum=item.attrib["sha256"]
    if "md5" in item.attrib:
        md5sum=item.attrib["md5"]
    if "FileOffsetInSrc" in item.attrib:
        start = int(item.attrib["FileOffsetInSrc"]) * pagesize
    elif "SizeInSectorInSrc" in item.attrib:
        start = int(item.attrib["SizeInSectorInSrc"]) * pagesize
    if "SizeInByteInSrc" in item.attrib:
        rlength = int(item.attrib["SizeInByteInSrc"])
    if "SizeInSectorInSrc" in item.attrib:
        length = int(item.attrib["SizeInSectorInSrc"]) * pagesize
    else:
        length=rlength
    return wfilename, start, length, rlength,[sha256sum,md5sum],decryptsize
        
def main():
    global cpcount, invalidsuper, fatalerror
    print("=====================================================")
    print(" TRUE OFP FLASHER - REALME X SAFE EDITION (A.05 FIX)")
    print("=====================================================\n")
    filesofp = []
    for file in os.listdir():
        if os.path.splitext(file)[1] == ".ofp":
            filesofp.append(file)
    if len(filesofp) < 1:
        print("ERROR: No .ofp files were found in the folder!")
        byebye()
    elif len(filesofp) > 1:
        for i, f in enumerate(filesofp): print(f"{i+1} - {f}")
        try: choice = int(input("Choice: ")) - 1
        except: choice = 0
        ofpfile = filesofp[choice]
    else:
        ofpfile = filesofp[0]
        print(f"File found: {ofpfile}")

    pk=False
    with open(ofpfile,"rb") as rf:
        if rf.read(2)==b"PK": pk=True
    if not pk:
        pagesize,key,iv,data=generatekey(ofpfile)
    if pk==True or pagesize==0:
        print("ERROR: Corrupt or incompatible file!")
        byebye()
    xml=data[:data.rfind(b">")+1].decode('utf-8')
    root = ET.fromstring(xml)
    print("OK: OFP Decrypted")
    
    regions = []
    for child in root:
        for item in child:
            if child.tag != "NVList": continue
            found = False
            for subregion in regions:
                if subregion[2] == item.attrib.get("super0", "") and subregion[3] == item.attrib.get("super1", "") and subregion[4] == item.attrib.get("super2", ""):
                    found = True
                    break
            if not found:
                regions.append((item.attrib.get("id", ""), item.attrib.get("text", ""), item.attrib.get("super0", ""), item.attrib.get("super1", ""), item.attrib.get("super2", "")))
    
    # NEW A.05 FIX: Safely handle missing Region/NVList tags in Android 9 firmware
    if len(regions) == 0:
        region = (None, "Default", "", "", "")
    else:
        region = regions[0]
        if len(regions) > 1:
            print("\nRegions:")
            for i, x in enumerate(regions): print(f"{i+1} - {x[1]} - [ID: {x[0]}]")
            try: region = regions[int(input("Choice: "))-1]
            except: region = regions[0]

    print("\n>> Waiting for device in fastboot mode to start <<")
    try: subprocess.check_output(["adb", "reboot", "bootloader"], stderr=subprocess.STDOUT)
    except: pass
        
    while True:
        try:
            out = subprocess.check_output(["fastboot", "devices"], stderr=subprocess.STDOUT).decode()
            if "fastboot" in out: break
        except FileNotFoundError:
            print("ERROR: fastboot not found. Install Android Platform Tools.")
            byebye()
        time.sleep(1)

    partitions = []
    try:
        allvar = subprocess.check_output(["fastboot", "getvar", "all"], stderr=subprocess.STDOUT).decode()
        for line in allvar.split("\n"):
            line = line.replace(" ", "").replace("\r", "")
            if "partition-type" in line:
                partition = line.replace("(bootloader)partition-type:", "").split(":")[0]
                partitions.append(partition)
    except subprocess.CalledProcessError:
        print("INFO: 'getvar all' rejected by device (normal for Realme X). Proceeding with OFP map.")

    blacklist = ["ocdt", "oppodycnvbk", "oppostanvbk", "opporeserve1", "modem", "persist"]
    
    if input("\nKeep userdata (apps/files)? Recommended unless bootlooping. [Y/n]: ").lower() != 'n':
        blacklist.append('userdata')

    print("\nStarting process....\nNote: this may take a while, it will make some popcorn for now.")
    path = tempfile.mkdtemp()
    xmlfiles = []
    
    for child in root:
        for item in child:
            if "Path" not in item.attrib and "filename" not in item.attrib:
                for subitem in item:
                    wfilename, start, length, rlength, checksums, decryptsize = decryptitem(subitem, pagesize)
                    if wfilename=="" or start==-1: continue
                    xmlfiles.append((wfilename, start, length, rlength, checksums, decryptsize, False))
            wfilename, start, length, rlength, checksums, decryptsize = decryptitem(item, pagesize)
            iscopy = False
            if wfilename=="" or start==-1: continue
            if child.tag in ["Sahara"]: decryptsize=rlength
            if child.tag in ["Config","Provision","ChainedTableOfDigests","DigestsToSign", "Firmware"]: length=rlength
            if child.tag in ["DigestsToSign","ChainedTableOfDigests", "Firmware"]: iscopy = True
            xmlfiles.append((wfilename, start, length, rlength, checksums, decryptsize, iscopy))

    for child in root:
        for item in child:
            if child.tag != "ProgramList" or item.attrib.get("filename", "") == "": continue
            
            label = item.attrib["label"]
            if label in blacklist: continue
            if len(partitions) > 0 and label not in partitions: continue
                
            for file in xmlfiles:
                if item.attrib["filename"] == file[0] and "ddr4" not in file[0] and "ddr5" not in file[0]:
                    if file[6]:
                        copy(ofpfile, path, f'{label}.img', file[1], file[2], file[4])
                    else:
                        decryptfile(False, key, iv, ofpfile, path, f'{label}.img', file[1], file[2], file[3], file[4], file[5])
                        
    if len(regions) >= 1 and region[2] != "":
        print("\nEXTRACTING: super partition")
        for file in xmlfiles:
            if file[0] in [region[2], region[3], region[4]]:
                decryptfile(True, key, iv, ofpfile, path, "super0.img" if "super.0" in file[0] else "super1.img" if "super.1" in file[0] else "super2.img", file[1], file[2], file[3], file[4], file[5])
        if invalidsuper:
            print("EXTRACT ERROR: Error on hashes. OFP super partition might be broken!")
        else:
            s0, s1, s2, sm = os.path.join(path, "super0.img"), os.path.join(path, "super1.img"), os.path.join(path, "super2.img"), os.path.join(path, "super.img")
            chunks = [c for c in [s0, s1, s2] if os.path.exists(c)]
            if chunks:
                print("MERGING: Sparse chunks via simg2img...")
                try:
                    subprocess.check_output(["simg2img"] + chunks + [sm], stderr=subprocess.STDOUT)
                    flashpartition("super", sm)
                except Exception as e:
                    print("EXTRACT ERROR: simg2img failed. Flashing chunks manually.")
                    for c in chunks: flashpartition("super", c)
                
    shutil.rmtree(path)
    
    if fatalerror == "":
        print("\nDone. Firmware flashed successfully!")
        try:
            subprocess.check_output(["fastboot", "reboot"], stderr=subprocess.STDOUT)
            print("Rebooting device...")
        except:
            print("Please manually reboot your device.")
    else:
        print(f"\nFATALERROR: {fatalerror}")
        
    byebye()

if __name__=="__main__":
    main()