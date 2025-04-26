
rule TrojanDownloader_O97M_Obfuse_RVBZ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVBZ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 6f 62 6a 65 63 74 28 6f 74 74 61 77 61 29 2e 63 72 65 61 74 65 6f 62 6a 65 63 74 28 63 68 61 70 74 65 72 73 29 2e 72 75 6e 66 69 73 74 69 6e 67 } //1 getobject(ottawa).createobject(chapters).runfisting
		$a_01_1 = {63 68 72 28 28 37 2a 32 29 2b 28 28 28 31 30 2d 34 29 2a 32 29 2a 32 29 29 26 63 68 72 28 28 28 28 31 36 2f 32 29 2a 32 29 2b 28 34 2a 35 29 29 2a 32 29 26 6d 69 64 28 69 6e 74 72 6f 64 75 63 65 2c 69 2b 31 2c 32 29 69 3d 69 2b 32 } //1 chr((7*2)+(((10-4)*2)*2))&chr((((16/2)*2)+(4*5))*2)&mid(introduce,i+1,2)i=i+2
		$a_01_2 = {77 6f 72 6b 62 6f 6f 6b 5f 6f 70 65 6e 28 29 66 6c 6f 72 65 6e 63 65 6d 69 6c 6c 73 28 73 68 65 65 74 73 28 22 6c 37 34 37 66 22 29 2e 72 61 6e 67 65 28 22 65 31 35 30 22 29 2e 76 61 6c 75 65 29 } //1 workbook_open()florencemills(sheets("l747f").range("e150").value)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}