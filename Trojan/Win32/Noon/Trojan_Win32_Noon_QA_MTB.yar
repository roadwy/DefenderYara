
rule Trojan_Win32_Noon_QA_MTB{
	meta:
		description = "Trojan:Win32/Noon.QA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {61 6c 67 7a 69 66 7a } //algzifz  3
		$a_80_1 = {50 61 74 68 55 6e 71 75 6f 74 65 53 70 61 63 65 73 41 } //PathUnquoteSpacesA  3
		$a_80_2 = {53 48 52 65 67 44 65 6c 65 74 65 45 6d 70 74 79 55 53 4b 65 79 41 } //SHRegDeleteEmptyUSKeyA  3
		$a_80_3 = {47 6f 70 68 65 72 46 69 6e 64 46 69 72 73 74 46 69 6c 65 57 } //GopherFindFirstFileW  3
		$a_80_4 = {46 74 70 47 65 74 46 69 6c 65 41 } //FtpGetFileA  3
		$a_80_5 = {52 65 74 72 69 65 76 65 55 72 6c 43 61 63 68 65 45 6e 74 72 79 46 69 6c 65 41 } //RetrieveUrlCacheEntryFileA  3
		$a_80_6 = {46 74 70 53 65 74 43 75 72 72 65 6e 74 44 69 72 65 63 74 6f 72 79 41 } //FtpSetCurrentDirectoryA  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}