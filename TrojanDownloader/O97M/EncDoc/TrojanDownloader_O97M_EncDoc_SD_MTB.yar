
rule TrojanDownloader_O97M_EncDoc_SD_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 63 68 72 28 28 37 2a 32 29 2b 28 28 28 31 30 2d 34 29 2a 32 29 2a 32 29 29 26 63 68 72 28 28 28 28 31 36 2f 32 29 2a 32 29 2b 28 34 2a 35 29 29 2a 32 29 26 6d 69 64 28 74 72 61 6d 61 64 6f 6c 2c 69 2b 31 2c 32 29 69 3d 69 2b 32 } //1 =chr((7*2)+(((10-4)*2)*2))&chr((((16/2)*2)+(4*5))*2)&mid(tramadol,i+1,2)i=i+2
		$a_01_1 = {73 75 62 73 75 62 77 6f 72 6b 62 6f 6f 6b 5f 6f 70 65 6e 28 29 69 6e 76 6f 6c 76 65 64 69 76 69 6e 67 28 73 68 65 65 74 73 28 22 73 36 61 34 64 22 29 2e 72 61 6e 67 65 28 22 68 31 30 31 22 29 2e 76 61 6c 75 65 29 2c 64 69 76 69 6e 67 28 73 68 65 65 74 73 28 22 73 36 61 34 64 22 29 2e 72 61 6e 67 65 28 22 65 31 31 38 22 29 2e 76 61 6c 75 65 29 2c 64 69 76 69 6e 67 28 73 68 65 65 74 73 28 22 73 36 61 34 64 22 29 } //1 subsubworkbook_open()involvediving(sheets("s6a4d").range("h101").value),diving(sheets("s6a4d").range("e118").value),diving(sheets("s6a4d")
		$a_01_2 = {67 65 74 6f 62 6a 65 63 74 28 61 6c 69 63 65 29 2e 63 72 65 61 74 65 6f 62 6a 65 63 74 28 69 6e 74 72 6f 29 2e 72 75 6e 63 79 63 6c 69 6e 67 } //1 getobject(alice).createobject(intro).runcycling
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}