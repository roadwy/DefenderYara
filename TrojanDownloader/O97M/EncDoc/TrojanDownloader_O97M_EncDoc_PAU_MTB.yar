
rule TrojanDownloader_O97M_EncDoc_PAU_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PAU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {31 22 73 75 62 61 75 74 6f 5f 6f 70 65 6e 28 29 64 65 62 75 67 2e 70 72 69 6e 74 6d 73 67 62 6f 78 28 63 68 72 24 28 36 39 29 26 63 68 72 24 28 38 32 29 26 63 68 72 24 28 38 32 29 26 63 68 72 24 28 37 39 29 26 63 68 72 24 28 38 32 } //1 1"subauto_open()debug.printmsgbox(chr$(69)&chr$(82)&chr$(82)&chr$(79)&chr$(82
		$a_01_1 = {3d 63 68 72 24 28 39 39 29 26 63 68 72 24 28 35 38 29 26 63 68 72 24 28 39 32 29 26 63 68 72 24 28 31 31 39 29 26 63 68 72 24 28 31 30 35 29 26 63 68 72 24 28 31 31 30 29 26 63 68 72 24 28 31 30 30 29 26 63 68 72 24 28 31 31 31 29 26 63 68 72 24 28 } //1 =chr$(99)&chr$(58)&chr$(92)&chr$(119)&chr$(105)&chr$(110)&chr$(100)&chr$(111)&chr$(
		$a_01_2 = {2e 70 72 69 6e 74 6f 66 6c 62 65 68 76 68 75 64 65 62 75 67 2e 70 72 69 6e 74 28 76 62 61 2e 73 68 65 6c 6c 28 76 70 68 70 67 72 71 7a 79 2b 6f 77 32 69 75 76 65 6f 61 2b 77 77 68 72 6b 62 39 34 6f 66 6c 62 65 68 76 68 75 2b 6f 66 6c 62 65 68 76 68 75 29 29 65 6e 64 73 } //1 .printoflbehvhudebug.print(vba.shell(vphpgrqzy+ow2iuveoa+wwhrkb94oflbehvhu+oflbehvhu))ends
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}