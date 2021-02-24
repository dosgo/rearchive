package hash

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)


var verbose bool=false;
var Out ="";

var d_FHFL_UTIME   uint64   = 0x0002;
var d_FHFL_CRC32   uint64   = 0x0004;
var d_HEAD_MARK    =0x00
var d_HEAD_MAIN   = 0x01
var d_HEAD_FILE   = 0x02
var d_HEAD_SERVICE= 0x03
var d_HEAD_CRYPT  =0x04;
var d_HEAD_ENDARC  =0x05
var d_LINE_BUFFER_SIZE =0x10000
var d_FHEXTRA_CRYPT   =0x01
var d_HFL_EXTRA     uint64=    1
var d_HFL_DATA     uint64 =    2
var d_HFL_SKIPIFUNKNOWN uint64 =4


var d_MHFL_VOLUME   =  0x0001
var d_MHFL_VOLNUMBER  uint64=0x0002
var d_MHFL_SOLID   =   0x0004
var d_MHFL_PROTECT   = 0x0008



type bestSize struct {
	pack uint32
	unp uint32
	method uint8
}

func isLittleEndian() bool {
	n := 0x1234
	f := *((*byte)(unsafe.Pointer(&n)))
	return (f ^ 0x34) == 0
}

/* Derived from unrar's encname.cpp */
 func decodeFileName( Name string , EncName []byte,  EncSize int,  MaxDecSize int) []byte{

 	var Flags byte = 0;
	var FlagBits int32 = 0;
	 var EncPos  = 0
	 var DecPos = 0;

	EncPos=EncPos+1;
	var HighByte byte = EncName[EncPos]
	var NameW []byte
	MaxDecSize /= 2;

	for EncPos < EncSize - 1 && DecPos < MaxDecSize - 1 {
		if FlagBits == 0{
			EncPos=EncPos+1
			Flags = EncName[EncPos];
			FlagBits = 8;
		}
		switch(Flags >> 6){
		case 0:
				DecPos++
				EncPos++
				if isLittleEndian() {
					NameW[DecPos] = EncName[EncPos];
				}else {
					NameW[DecPos] = EncName[EncPos] << 8;
				}
			break;
		case 1:
			DecPos++
			EncPos++
			if isLittleEndian() {
				NameW[DecPos] = EncName[EncPos] + (HighByte << 8);
			}else {
				NameW[DecPos] = (EncName[EncPos] << 8) + HighByte;
			}
			break;
		case 2:
			DecPos++
			if isLittleEndian() {
				NameW[DecPos] = EncName[EncPos] +(EncName[EncPos+1]<<8);
			}else {
				NameW[DecPos] = (EncName[EncPos] << 8) +EncName[EncPos+1];
			}
			EncPos+=2;
			break;
		case 3:
			{
			EncPos++
			var  Length = EncName[EncPos];
			if (Length & 0x80)>0 {
				EncPos++
				var Correction byte = EncName[EncPos];
				for Length = (Length & 0x7f) + 2; Length>0 && DecPos < MaxDecSize;  DecPos++{
					if isLittleEndian(){
						NameW[DecPos] = ((Name[DecPos] +Correction) & 0xff) + (HighByte << 8);
					}else{
						NameW[DecPos] = (((Name[DecPos] +Correction) & 0xff) << 8) + HighByte;
					}
					Length--
				}
			} else {
				for Length += 2; Length > 0 && DecPos < MaxDecSize;  DecPos++{
					if isLittleEndian() {
						NameW[DecPos] = Name[DecPos];
					} else {
						NameW[DecPos] = Name[DecPos] << 8;
					}
					Length--;
				}
			}
		}
		break;
		}
		Flags <<= 2;
		FlagBits -= 2;
	}
	return NameW;
}



 func Rar2HashFile(archive_name string) int{
 	var fp *os.File;
 	var marker_block = make([]byte, 7)
 	var archive_hdr_block = make([]byte, 13)
 	var file_hdr_block = make([]byte, 40)
	var  i int
 	var _type int;
 	var bestsize=&bestSize{}

	var buf = make([]byte, 4096)

	//var  archive_hdr_head_flags uint16
	var file_hdr_head_flags uint16

	var  diff int;
	var  found = 0;
	var gecos="";
	var best="";
	var base_aname =filepath.Base(archive_name);

	 fp,err:= os.Open(archive_name);
	 if err!=nil {
		 fmt.Printf("! %s: %s\n",err.Error())
		 return -1;
	 }
	 defer fp.Close();

	/* marker block */
	 _,err=fp.Read(marker_block)
	 if err!=nil {
		 log.Printf("! %s: %s\n",err.Error())
		 return -1;
	 }

	 if !bytes.Equal(marker_block,[]byte{0x52,0x61,0x72,0x21,0x1a,0x07,0x00}) {
		/* handle SFX archives */
		if (bytes.Equal(marker_block[:2], []byte{0x4d,0x5a})) {
			/* jump to "Rar!" signature */
			for  {
				count,err:=fp.Read(buf)
				if (err!=nil) {
					break;
				}
				pos := strings.IndexAny(string(buf),string([]byte{0x52,0x61,0x72,0x21,0x1a,0x07,0x00}))
				if (pos >0) {
					diff = count - pos;
					fp.Seek(int64(-diff),syscall.FILE_CURRENT)
					fp.Seek(7,syscall.FILE_CURRENT)
					found = 1;
					break;
				}

				//jtr_fseek64(fp, -6, SEEK_CUR);
				fp.Seek(-6,syscall.FILE_CURRENT)
			}
			if found==0 {
				if process_file5(archive_name)!=0 {
					fmt.Fprintf(os.Stderr, "! %s: Not a RAR file\n", archive_name);
					return -1;
				}
				return 0;
			}
		} else {
			/* try to detect RAR 5 files */
			if process_file5(archive_name)!=0 {
				fmt.Fprintf(os.Stderr, "! %s: Not a RAR file\n", archive_name);
				return -1;
			}
			return 0;
		}
	}

	/* archive header block */
	_,err= fp.Read(archive_hdr_block)
	if err!=nil {
		log.Printf( "%s: Error8: read failed: %s.\n", archive_name, err.Error());
		return -1;
	}
	if archive_hdr_block[2] != 0x73 {
		fmt.Fprintf(os.Stderr, "%s: Error: archive_hdr_block[2] must be 0x73.\n",
			archive_name);
		return -1;
	}

	/* find encryption mode used (called type in output line format) */
	//var archive_hdr_head_flags = archive_hdr_block[4] << 8 | archive_hdr_block[3];
	var archive_hdr_head_flags = binary.LittleEndian.Uint16(archive_hdr_block[3:5])

	if (archive_hdr_head_flags & 0x0080)>0 {	/* file header block is encrypted */
		_type = 0;	/* RAR file was created using -hp flag */
	} else {
		_type = 1;
	}

	/*
	 * We need to skip ahead, if there is a comment block in the main header.
	 * It causes that header tp be larger that a simple 13 byte block.
	 */
	var head_size = binary.LittleEndian.Uint16(archive_hdr_block[5:7])

	if (head_size > 13) {
		fp.Seek(int64(head_size-13),syscall.FILE_CURRENT)
	}

next_file_header:
	if verbose {
		fmt.Fprintf(os.Stderr, "\n");
	}

	/* file header block */
	_,err=fp.Read(file_hdr_block[:32])
	fInfo,_:=fp.Stat()
	_cuPos,_:=fp.Seek(0,syscall.FILE_CURRENT)
	if err!=nil||fInfo.Size()==_cuPos {
		if verbose {
			fmt.Fprintf(os.Stderr, "! %s: End of file\n", archive_name);
		}
		bailOut(best,bestsize,gecos,base_aname);
		if err!=nil {
			return -1;
		}
		return 0;
	}

	if _type == 1 && file_hdr_block[2] == 0x7a {
		if verbose {
			fmt.Fprintf(os.Stderr, "! %s: Comment block present?\n", archive_name);
		}
	}else if _type == 1 && file_hdr_block[2] != 0x74 {
		fmt.Fprintf(os.Stderr, "! %s: Not recognising any more headers.\n", archive_name);
		bailOut(best,bestsize,gecos,base_aname);
		return -1;
	}

	 file_hdr_head_flags = binary.LittleEndian.Uint16(file_hdr_block[3:5])

	/* process -hp mode files
	   use Marc's end-of-archive block decrypt trick */
	if _type == 0 {
		//unsigned char buf[24];
		var buf=make([]byte,24);

		if verbose {
			fmt.Fprintf(os.Stderr, "! -hp mode entry found in %s\n", base_aname);
		}
		fmt.Printf("%s:$RAR3$*%d*", base_aname, _type);
		Out=fmt.Sprintf("%s:$RAR3$*%d*", base_aname, _type)
		fp.Seek(-24,syscall.FILE_END)
		_,err=fp.Read(buf);
		if err!= nil {
			log.Printf( "%s: Error2: read failed: %s.\n", archive_name, err.Error());
			return -1;
		}

		/* encode salt */
		fmt.Printf("%s", hex.EncodeToString(buf[:8]));
		Out= fmt.Sprintf("%s%s",Out, hex.EncodeToString(buf[:8]));


		fmt.Printf("*");
		Out= fmt.Sprintf("%s*",Out);

		/* encrypted block with known plaintext */
		fmt.Printf("%s", hex.EncodeToString(buf[8:]));
		Out= fmt.Sprintf("%s%s",Out, hex.EncodeToString(buf[8:]));

		fmt.Printf(":%d::::%s\n", _type, archive_name);
		Out=fmt.Sprintf("%s:%d::::%s\n",Out, _type, archive_name)
	} else {
		var  file_hdr_pack_size uint32 = 0
		var file_hdr_unp_size uint32= 0;
		var  method uint8;
		var file_crc=make([]byte,4)
		var salt=make([]byte,8);
		 var rejbuf = make([]byte, 32)


		if (file_hdr_head_flags & 0x8000)==0 {
			fmt.Fprintf(os.Stderr, "File header flag 0x8000 unset, bailing out.\n");
			bailOut(best,bestsize,gecos,base_aname);
			return -1;
		}

		var file_hdr_head_size = binary.LittleEndian.Uint16(file_hdr_block[5:7])

		/*
		 * Low 32 bits.  If header_flags & 0x100 set, then there are additional
		 * 32 bits of length data later in the header. FIXME!
		 */

		file_hdr_pack_size=binary.LittleEndian.Uint32(file_hdr_block[7:11])
		file_hdr_unp_size=binary.LittleEndian.Uint32(file_hdr_block[11:15])

		if verbose {
			fmt.Fprintf(os.Stderr, "! HEAD_SIZE: %d, PACK_SIZE: %d, UNP_SIZE: %d\n",
			        file_hdr_head_size,
			        file_hdr_pack_size,
			        file_hdr_unp_size);
			fmt.Fprintf(os.Stderr, "! file_hdr_block:\n!  ");
			for i = 0; i < 32; i++{
				fmt.Fprintf(os.Stderr, " %02x", file_hdr_block[i]);
			}
			fmt.Fprintf(os.Stderr, "\n");
		}
		/* calculate EXT_TIME size */
		var ext_time_size = file_hdr_head_size - 32;

		if (file_hdr_head_flags & 0x100)>0 {
			_,err=fp.Read(rejbuf[:4])
			if (err!= nil) {
				log.Printf( "\n! %s: Error3: read failed: %s.\n", archive_name,err.Error());
				return -1;
			}
			if verbose {
				fmt.Fprintf(os.Stderr, "!  ");
				for i = 0; i < 4; i++{
					fmt.Fprintf(os.Stderr, " %02x", rejbuf[i]);
				}
			}
			file_hdr_pack_size=file_hdr_pack_size+ binary.LittleEndian.Uint32(rejbuf[:5])
			ext_time_size -= 4;
			_,err=fp.Read(rejbuf[:4])
			if (err!= nil) {
				log.Printf( "\n! %s: Error4: read failed: %s.\n", archive_name, err.Error());
				return -1;
			}
			if verbose {
				for i = 0; i < 4; i++{
					fmt.Fprintf(os.Stderr, " %02x", rejbuf[i]);
				}
				fmt.Fprintf(os.Stderr, "   (High Pack/Unp extra header data)\n");
			}
			file_hdr_unp_size=file_hdr_unp_size+ binary.LittleEndian.Uint32(rejbuf[:5])
			ext_time_size -= 4;
			if verbose {
				fmt.Fprintf(os.Stderr, "! HIGH_PACK_SIZE present\n");
				fmt.Fprintf(os.Stderr, "! HIGH_UNP_SIZE present\n");
				//if (4 < 8) {
					//fmt.Fprintf(os.Stderr, "! %s: Error: File contains 64-bit sizes but this build of %s doesn't support it.\n", archive_name);
				//	return -1;
				//}
			}
		}

		/* file name processing */
		var file_name_size = binary.LittleEndian.Uint16(file_hdr_block[26:28])
		if verbose {
			fmt.Fprintf(os.Stderr, "! file name size: %d bytes\n", file_name_size);
		}

		 var fileName = make([]byte, file_name_size)
		 fmt.Printf("")
		 _,err=fp.Read(fileName)
		if err!= nil {
			if err!=io.EOF {
				log.Printf("! %s: Error5: read failed: %s.\n", archive_name, err.Error());
			}
			return -1;
		}

		ext_time_size =ext_time_size- file_name_size;

		/* If this flag is set, file_name contains some weird
		   wide char encoding that need to be decoded to UTF16
		   and then to UTF-8 (we don't support codepages here) */
		if (file_hdr_head_flags & 0x200)>0 {
			var FileNameW=make([]byte,256)
			var  Length = len(fileName);

			if verbose {
				//hexdump("! Encoded filenames", file_name, file_name_size);
				fmt.Fprintf(os.Stderr, "OEM name:  %s\n", fileName);
			}
			FileNameW=decodeFileName(string(fileName), fileName[Length+1:], int(file_name_size), 256);
			if (len(FileNameW)>0) {
				if verbose {
					fmt.Fprintf(os.Stderr, "OEM name:  %s\n", fileName);
				}
				fmt.Fprintf(os.Stderr, " Unicode:   %s\n", fileName);
			} else {
				fmt.Fprintf(os.Stderr, " UTF8 name: %s\n", fileName);
			}
		} else{
			 fmt.Fprintf(os.Stderr, "! file name: %s\n", fileName);
		}

		/* We duplicate file names to the GECOS field, for single mode */
		if len(fileName) < d_LINE_BUFFER_SIZE {
			gecos=fmt.Sprintf("%s%s ",gecos,fileName)
		}

		/* salt processing */
		if (file_hdr_head_flags & 0x400)>0 {
			ext_time_size -= 8;
			_,err=fp.Read(salt)
			if (err!= nil) {
				log.Printf("! %s: Error6: read failed: %s.\n", archive_name,err.Error());
				return -1;
			}
		}

		/* EXT_TIME processing */
		if (file_hdr_head_flags & 0x1000)>0 {
			if verbose {
				fmt.Fprintf(os.Stderr, "! EXT_TIME present with size %d\n", ext_time_size);
			}
			_,err=fp.Read(rejbuf[:ext_time_size])
			if (err != nil) {
				log.Printf( "! %s: Error7: read failed: %s.\n", archive_name, err.Error());
				return -1;
			}
		}

		/* Skip solid files (first file is never solid)
		 * We could probably add support for this
		 */
		if (file_hdr_head_flags & 0x10)>0 {
			fmt.Fprintf(os.Stderr, "! Solid, can't handle (currently)\n");
			fp.Seek(int64(file_hdr_pack_size),syscall.FILE_CURRENT)
			goto next_file_header;
		}

		if (file_hdr_head_flags & 0xe0)>>5 == 7 {
			if verbose {
				fmt.Fprintf(os.Stderr, "! Is a directory, skipping\n");
			}
			fp.Seek(int64(file_hdr_pack_size),syscall.FILE_CURRENT)
			goto next_file_header;
		} else if verbose {
			 fmt.Fprintf(os.Stderr, "! Dictionary size: %u KB\n", 64<<((file_hdr_head_flags & 0xe0)>>5));
		}

		/* Check if encryption is being used */
		if (file_hdr_head_flags & 0x04)==0 {
			fmt.Fprintf(os.Stderr, "! not encrypted, skipping\n");
			fp.Seek(int64(file_hdr_pack_size),syscall.FILE_CURRENT)
			goto next_file_header;
		}

		method = file_hdr_block[25];

		/*
		 * Prefer shortest pack size, but given two files with single-block
		 * pack size, prefer unpack size >= 8. This gives us better immunity
		 * against false positives.
		 */
		var unp1 uint32=1;
		if bestsize.method > 0x30 {
			unp1=4;
		}
		var unp2 uint32=1;
		if method > 0x30 {
			unp2=4;
		}


		if (bestsize.pack < 4096 && (((bestsize.pack < file_hdr_pack_size && bestsize.unp >= unp1) ||(bestsize.unp > file_hdr_unp_size && file_hdr_unp_size < (unp2))) ||
			(bestsize.pack == file_hdr_pack_size && ((bestsize.unp > file_hdr_unp_size && file_hdr_unp_size < 8) || (bestsize.unp <= file_hdr_unp_size && bestsize.unp >= 8))))) {
			if verbose{
				fmt.Fprintf(os.Stderr, "! We got a better candidate already, skipping\n");
			}
			fp.Seek(int64(file_hdr_pack_size),syscall.FILE_CURRENT)
			goto next_file_header;
		}

		if verbose{
			fmt.Fprintf(os.Stderr, "! This is best candidate so far\n");
		}
		bestsize.pack = file_hdr_pack_size;
		bestsize.unp = file_hdr_unp_size;
		bestsize.method = method;




		/* process encrypted data of size "file_hdr_pack_size" */
		best = fmt.Sprintf("%s:$RAR3$*%d*", base_aname, _type);
		/* encode salt */
		best= fmt.Sprintf("%s%s",best, hex.EncodeToString(salt[:8]));

		if verbose {
			fmt.Fprintf(os.Stderr, "! salt: '%s'\n", best);
		}
		best = fmt.Sprintf("%s*",best);

		copy(file_crc, file_hdr_block[16:21])
		/* encode file_crc */
		best= fmt.Sprintf("%s%s",best, hex.EncodeToString(file_crc));

		if verbose {
			/* Minimal version needed to unpack this file */
			fmt.Fprintf(os.Stderr, "! UNP_VER is %0.1f\n", file_hdr_block[24] / 10.);
		}
		/*
		 * 0x30 - storing
		 * 0x31 - fastest compression
		 * 0x32 - fast compression
		 * 0x33 - normal compression (default)
		 * 0x34 - good compression
		 * 0x35 - best compression
		 *
		 * m3b means 0x33 and a dictionary size of 128KB (a == 64KB .. g == 4096KB)
		 */
		if verbose {
			fmt.Fprintf(os.Stderr, "! METHOD is m%x%c\n", method - 0x30, 'a'+((file_hdr_head_flags&0xe0)>>5));
			//fprintf(stderr, "! file_hdr_flags is 0x%04x\n", file_hdr_head_flags);
		}

		best= fmt.Sprintf( "%s*%d*%d*",best, file_hdr_pack_size, file_hdr_unp_size);

		/* We always store it inline */

		best =  fmt.Sprintf( "%s1*",best);
		var p string;
		var bytes_left = file_hdr_pack_size;
		var _bytes=make([]byte,64*1024)
		var  to_read = 64*1024;
		for i = 0; i < int(file_hdr_pack_size); i++ {

			if (bytes_left < 64*1024) {
				to_read = int(bytes_left);
			}
			bytes_left =bytes_left-uint32(to_read);
			n,err:=fp.Read(_bytes[:to_read])
			if n!=to_read||err!=nil {
				fmt.Fprintf(os.Stderr, "! Error while reading archive\n");
			}
			p= fmt.Sprintf("%s%s",p, hex.EncodeToString(_bytes[:to_read]));
		}

		best= fmt.Sprintf("%s%s*%02x:%d::", best,p,method, _type);

		/* Keep looking for better candidates */
		goto next_file_header;

	}
	return 0;
}

 func bailOut(best string,bestsize *bestSize,gecos string,base_aname string){
	 if len(best)>0 {
		 if verbose {
			 fmt.Fprintf(os.Stderr, "! Found a valid -p mode candidate in %s\n", base_aname);
		 }
		 var _nup uint32=1;
		 if(bestsize.method > 0x30){
			 _nup=5
		 }
		 if bestsize.unp <_nup{
			 fmt.Fprintf(os.Stderr, "! WARNING best candidate found is too small, you may see false positives.\n");
		 }
		 best=fmt.Sprintf("%s%s",best,gecos)
		 fmt.Print(best)
		 Out=fmt.Sprintf("%s%s",Out, best)
	 } else{
		 fmt.Fprintf(os.Stderr, "! Did not find a valid encrypted candidate in %s\n", base_aname);
	 }
	// os.Exit(-1);
 }

/**************************************************************************
 * Here are the functions and tools for RAR5
 *************************************************************************/
var d_CRYPT_VERSION     =0
var d_CHFL_CRYPT_PSWCHECK uint64=     1
var d_CRYPT5_KDF_LG2_COUNT= 15

var d_SIZE_SALT50 =16
var d_FHEXTRA_CRYPT_PSWCHECK uint64=0x01;
var d_FHEXTRA_CRYPT_HASHMAC = 0x02;
var d_CRYPT5_KDF_LG2_COUNT_MAX uint8 =24;
var d_SIZE_PSWCHECK =8;
var d_CHUNK_SIZE =4096;
var d_SIZE_PSWCHECK_CSUM=4
var d_SIZE_INITV =16


// global variables
var encrypted  int= 0;
var pswCheck=make([]byte,d_SIZE_PSWCHECK)
//static unsigned rar5_interations=0, UsePswCheck=0;
var rar5_interations uint32;
//static unsigned char rar5_salt[SIZE_SALT50];
var rar5_salt=make([]byte,d_SIZE_SALT50)

/**************************************************************************
 * These 4 functions do much of the reading for rar5 files. There is a
 * function to read a 4 byte int (in LE format), one to read a single
 * byte, one to to read a buffer, and one that reads the variable sized
 * numbers used in rar5 (LE format, 7 bits used per byte with high bit
 * used to signify if there are more bytes of data or not)
 *************************************************************************/
func read_uint32 (fp *os.File,  bytes_read uint32) (int,uint32,uint32) {
	var Buf=make([]byte,4);
	var n uint32= 0;
	_,err:=fp.Read(Buf)
	if err!=nil {
		return 0,n,bytes_read;
	}
	n=binary.LittleEndian.Uint32(Buf)
    bytes_read += 4;
	return 4,n,bytes_read;
}
func  read_uint8 (fp *os.File,  bytes_read uint32)(int,uint8,uint32) {
	var Buf=make([]byte,1)
	_,err:=fp.Read(Buf);
	var  n uint8
	if err!=nil {
		return 0,0,bytes_read;
	}
    n = Buf[0];
    bytes_read += 1;
	return 1,n,bytes_read;
}
func read_buf (fp *os.File, _len int,bytes_read uint32) ([]byte,int,uint32) {
	var cp=make([]byte,_len)
	_,err:=fp.Read(cp)
	if (err!=nil) {
		return nil,0,bytes_read;
	}
    bytes_read += uint32(_len);
	return cp,_len,bytes_read;
}
func read_vuint (fp *os.File, bytes_read uint32) (int,uint64,uint32) {
	//unsigned char c;
	var c=make([]byte,1);
	var  i int=0;
	var shift int=0;
    var  accum uint64;
	var n uint64 = 0;
	for i= 0; i < 10; i++ {
		_,err:=fp.Read(c)
		if err != nil{
			return 0,n,bytes_read;
		}
        accum = uint64((c[0] & 0x7f));
		n = n + (accum << shift);
		shift += 7;
		if (c[0] & 0x80) == 0 {
            bytes_read += uint32(i+1);
			return i + 1,n,bytes_read;
		}
	}
	return 0,n,bytes_read;
}

/**************************************************************************
 * Process an 'extra' block of data. This is where rar5 stores the
 * encryption block.
 *************************************************************************/
func processExtra50(fp *os.File,  extra_size uint64,  HeadSize uint64,  HeaderType uint32,  CurBlockPos uint32, archive_name string, found int) (int,int){
	var  FieldSize uint64
	var FieldType uint64
	//var EncVersion uint64
	var Flags uint64
	var  bytes_read uint32=0;
	var  bytes_left=int(extra_size);
	var Lg2Count byte;
	var base_aname = filepath.Base(archive_name)
	var n int;

   // fprintf(stderr, "in extra50 extrasize=%d\n", extra_size);
    for  {
		n,FieldSize,bytes_read= read_vuint(fp, bytes_read);
        if n==0 || n > 3 {
        	return 0,found;
        }  // rar5 technote (http://www.rarlab.com/technote.htm#arcblocks) lists max size of header len is 3 byte vint.
        bytes_left = bytes_left-n;
        bytes_left = bytes_left-int(FieldSize);
        if bytes_left < 0 {
        	return 0,found
        }
		n,FieldType,bytes_read=read_vuint(fp, bytes_read)
        if n==0 {
        	return 0,found
        }
        // fprintf(stderr, "in Extra50.  FieldSize=%d FieldType=%d\n", FieldSize, FieldType);
        if (int(HeaderType) == d_HEAD_FILE || int(HeaderType) == d_HEAD_SERVICE) {
            if (FieldType == uint64(d_FHEXTRA_CRYPT)) {
                var InitV=make([]byte,d_SIZE_INITV)
				//EncVersion
				n,_,bytes_read=read_vuint(fp,bytes_read)
                if (n==0) {
                	return 0,found
                }
				n,Flags,bytes_read=read_vuint(fp, bytes_read)
                if (n==0) {
                	return 0,found
                }
                if ( (Flags & d_FHEXTRA_CRYPT_PSWCHECK) == 0) {
                    fmt.Fprintf(os.Stderr, "UsePswCheck is OFF. We currently don't support such files!\n");
                    return 0,found
                }
                n,Lg2Count,bytes_read=read_uint8(fp, bytes_read)
                if (n==0){
                	return 0,found
                }
                if (Lg2Count >= d_CRYPT5_KDF_LG2_COUNT_MAX) {
					fmt.Fprintf(os.Stderr, "Lg2Count >= CRYPT5_KDF_LG2_COUNT_MAX (problem with file?)");
                    return 0,found
                }
				rar5_salt,n,bytes_read:=read_buf(fp, d_SIZE_SALT50, bytes_read)
                if (n==0){
                	return 0,found
                }
				InitV,n,bytes_read=read_buf(fp, d_SIZE_INITV, bytes_read)
				if n==0{
					return 0,found
				}
				pswCheck,n,bytes_read=read_buf(fp, d_SIZE_PSWCHECK, bytes_read)
                if n==0{
                	return 0,found
                }
                found++;
				tmpOut:=fmt.Sprintf("%s:$rar5$%d$%s$%d$%s$%d$%s\n",
                    base_aname, d_SIZE_SALT50, hex.EncodeToString(rar5_salt),
                    Lg2Count, hex.EncodeToString(InitV),
                    d_SIZE_PSWCHECK, hex.EncodeToString(pswCheck));
				fmt.Printf("%s",tmpOut)
				Out=fmt.Sprintf("%s%s",Out, tmpOut)
                return 0,found
            }
        }
    }
    return 1,found
 }

/**************************************************************************
 * Common file header processing for rar5
 *************************************************************************/

func read_rar5_header(fp *os.File,  CurBlockPos uint32, archive_name string,found int) (int64,uint8,int){
	var  block_size uint64
	var  flags uint64;
	var extra_size uint64
	var  data_size uint64;
	var  crypt_version uint64; var enc_flags uint64; var HeadSize uint64;
	//var  head_crc uint32;
	var header_bytes_read  uint32;
	var sizeof_vint int;
	var  HeaderType uint8;
	var  header_type uint8; var  lg_2count uint8;
	var base_aname = filepath.Base(archive_name)

    if encrypted==1 {
        // The header is encrypted, so we simply find the IV from this block.
        var HeadersInitV=make([]byte,d_SIZE_INITV)
		HeadersInitV,sizeof_vint,header_bytes_read = read_buf(fp,  d_SIZE_INITV, header_bytes_read);
        if sizeof_vint != d_SIZE_INITV {
            fmt.Fprintf(os.Stderr, "Error, rar file %s too short, could not read IV from header\n", archive_name);
            return 0, HeaderType,found;
        }
        found++;
		tmpOut:=fmt.Sprintf("%s:$rar5$%d$%s$%d$%s$%d$%s\n", base_aname, d_SIZE_SALT50,hex.EncodeToString(rar5_salt),
            rar5_interations, hex.EncodeToString(HeadersInitV),
            d_SIZE_PSWCHECK, hex.EncodeToString(pswCheck))
		fmt.Printf("%s",tmpOut)
		Out=fmt.Sprintf("%s%s",Out, tmpOut)
        return 0,HeaderType,found;
    }
    //head_crc
	n,_,header_bytes_read:=read_uint32(fp, header_bytes_read)
	if n==0 {
		return 0,HeaderType,found
	}


    sizeof_vint,block_size,header_bytes_read = read_vuint(fp, header_bytes_read);
    if (sizeof_vint==0) {
		return 0,HeaderType,found;
	}
    // The HeadSize is full size of this header from the start of the HeaderCRC, to the end of any 'extra-data' section.
    HeadSize = block_size + 4 + uint64(sizeof_vint);

	//if (!read_vuint(fp, &header_type, &header_bytes_read)) return 0;
	n,header_type,header_bytes_read=read_uint8(fp, header_bytes_read)
    if n==0 {
    	return 0,HeaderType,found
    }
	n,flags,header_bytes_read=read_vuint(fp, header_bytes_read)
    if n==0 {
    	return 0,HeaderType,found
	}
    HeaderType = header_type;
    if (flags & d_HFL_EXTRA) != 0 {
		n,extra_size,header_bytes_read=read_vuint(fp, header_bytes_read)
    	if n==0 {
    		return 0,HeaderType,found
    	}
    }
    if (flags & d_HFL_DATA) != 0 {
		n,data_size,header_bytes_read=read_vuint(fp, header_bytes_read)
    	if n==0 {
    		return 0,HeaderType,found
    	}
    }

    // fprintf(stderr, "curpos=%d bs=%d firstreadsize=%d, sizeBytes=%d headtye=%d flags=%d \n", NowCurPos, block_size, 7, SizeBytes, header_type, flags);

    if int(header_type) == d_HEAD_CRYPT {
       var chksum=make([]byte,d_SIZE_PSWCHECK_CSUM)
       var n int;
       n,crypt_version,header_bytes_read=read_vuint(fp, header_bytes_read)
       if n==0 {
       		return 0,HeaderType,found
       }
       if int(crypt_version) > d_CRYPT_VERSION {
       	  fmt.Printf("bad rar crypt version byte\n")
       	  return 0,HeaderType,found
       }
       n,enc_flags,header_bytes_read=read_vuint(fp,header_bytes_read)
       if n==0 {
       	  return 0,HeaderType,found
       }
       var UsePswCheck = (enc_flags & d_CHFL_CRYPT_PSWCHECK) != 0;  // set global
       n,lg_2count,header_bytes_read=read_uint8(fp, header_bytes_read)
       if n==0 {
       		return 0,HeaderType,found
       }
       if lg_2count> d_CRYPT5_KDF_LG2_COUNT_MAX {
	   		fmt.Printf("rar PBKDF2 iteration count too large\n");
	   		return 0,HeaderType,found
       }
        rar5_interations = uint32(lg_2count); // set global
       // fmt.Printf("rar5_interations:%d\r\n",rar5_interations)
       // get salt
		rar5_salt,n,header_bytes_read=read_buf(fp, d_SIZE_SALT50, header_bytes_read)
       if n==0 {
		   return 0,HeaderType,found
	   }
       if UsePswCheck {

		   pswCheck,n,header_bytes_read=read_buf(fp, d_SIZE_PSWCHECK, header_bytes_read)
           if n==0 {
           		return 0,HeaderType,found
           }
		   chksum,n,header_bytes_read=read_buf(fp, d_SIZE_PSWCHECK_CSUM, header_bytes_read)
           if n==0 {
			   return 0,HeaderType,found
		   }

		   sha256ch := sha256.Sum256(pswCheck)
           UsePswCheck =string(sha256ch[:32])==string(chksum);
       }
       encrypted = 1;
     } else if int(header_type) == d_HEAD_MAIN {
        var  ArcFlags uint64
       // var VolNumber uint64=0;
		n,ArcFlags,header_bytes_read=read_vuint(fp, header_bytes_read)
        if n==0 {
        	return 0,HeaderType,found
        }

        if ((ArcFlags & d_MHFL_VOLNUMBER) != 0){
        	//VolNumber
			n,_,header_bytes_read=read_vuint(fp, header_bytes_read)
			if n==0 {
				return 0,HeaderType,found
			}
		}
		//fmt.Printf("VolNumber:%d\r\n",VolNumber)
    } else if (int(header_type) == d_HEAD_FILE || int(header_type) == d_HEAD_SERVICE) {
       var   FileFlags uint64
     //  var UnpSize uint64
     //  var FileAttr uint64;
     	//var   CompInfo uint64;
     //	var HostOS uint64;
     	var  NameSize uint64;
     //  var   FileHashCRC32 uint32
     //  var tmp uint32;
		n,FileFlags,header_bytes_read=read_vuint(fp, header_bytes_read)
        if n==0 {
        	return 0,HeaderType,found
        }
		n,_,header_bytes_read=read_vuint(fp, header_bytes_read)
        if n==0 {
        	return 0,HeaderType,found
        }
		n,_,header_bytes_read=read_vuint(fp, header_bytes_read)
        if n==0 {
        	return 0,HeaderType,found
        }

        if (FileFlags & d_FHFL_UTIME) != 0 {
			n,_,header_bytes_read=read_uint32(fp, header_bytes_read)
            if n==0 {
            	return 0,HeaderType,found
            }
            //mtime = tmp;
        }

        if (FileFlags & d_FHFL_CRC32) != 0 {
			n,_,header_bytes_read=read_uint32(fp, header_bytes_read)
            if n==0 {
            	return 0,HeaderType,found;
            }
        }

		n,_,header_bytes_read=read_vuint(fp, header_bytes_read)
        if n==0 {
        	return 0,HeaderType,found;
        }

        n,_,header_bytes_read=read_vuint(fp, header_bytes_read)
        if n==0 {
        	return 0,HeaderType,found;
        }
		n,NameSize,header_bytes_read=read_vuint(fp, header_bytes_read)
        if n==0 {
        	return 0,HeaderType,found;
        }
        // skip the field name.
		fp.Seek(int64(NameSize),syscall.FILE_CURRENT)
        if extra_size != 0 {
			_,found=processExtra50(fp, extra_size, HeadSize, uint32(HeaderType), CurBlockPos, archive_name, found);
        }

    } else if int(header_type) == d_HEAD_ENDARC {
        return 0,HeaderType,found;
    }
	return int64(uint64(CurBlockPos)+HeadSize+data_size),HeaderType,found;
}

/* handle rar5 files */
func  process_file5(archive_name string) int {
	//fprintf(stderr, "! %s: Not a RAR 3.x file, try running rar5tojohn.py on me!\n", archive_name);
	//char Magic[8], buf[CHUNK_SIZE], *pos;
	var Magic=make([]byte,8);
	var buf=make([]byte,d_CHUNK_SIZE)
	var  count=0
	var NextBlockPos int64=0;
	var CurBlockPos int64=0;
	var  diff=0;
	var found = 0;
	var fp *os.File;
	fp,err:=os.Open(archive_name)
	if err!=nil {
		fmt.Fprintf(os.Stderr, "error opening file %s\n", archive_name);
		return 0;
	}
	_,err=fp.Read(Magic)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading rar signature from file %s\n", archive_name);
        return 0;
    }

	if bytes.Equal(Magic,[]byte{0x52,0x61,0x72,0x21,0x1a,0x07,0x01,0x00}) { /* handle SFX archives */

		if bytes.Equal(Magic[:2], []byte{0x4d,0x5a}) {
			/* jump to "Rar!" signature */
			for  {
				count,err=fp.Read(buf);
				if err!=nil {
					break;
				}

				pos := strings.IndexAny(string(buf),string([]byte{0x52,0x61,0x72,0x21,0x1a,0x07,0x01,0x00}))
				if pos>0 {
					diff = count -pos;
					fp.Seek(int64(-diff),syscall.FILE_CURRENT)
					fp.Seek(8,syscall.FILE_CURRENT)
					found = 1;
					break;
				}
				fp.Seek(-7,syscall.FILE_CURRENT)
			}
            if found==0 {
				return -1;
			}
		}
	}
	found = 0;
	for  {
		CurBlockPos,_=fp.Seek(0,syscall.FILE_CURRENT)
		NextBlockPos,_, found= read_rar5_header(fp, uint32(CurBlockPos), archive_name,found);
		if NextBlockPos==0 {
			break;
		}
		fp.Seek(NextBlockPos,syscall.FILE_BEGIN)
	}
    if found==0 {
		fmt.Fprintf(os.Stderr, "! Did not find a valid encrypted candidate in %s\n", archive_name);
		return 1;
	}
    return 0;
}










