
rule TrojanDownloader_Win32_Brucryp_C{
	meta:
		description = "TrojanDownloader:Win32/Brucryp.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 00 65 00 72 00 74 00 5f 00 76 00 25 00 64 00 5f 00 25 00 64 00 2e 00 74 00 70 00 6c 00 00 00 } //1
		$a_01_1 = {65 00 76 00 65 00 6e 00 74 00 74 00 6f 00 73 00 79 00 6e 00 63 00 74 00 72 00 74 00 68 00 00 00 } //1
		$a_03_2 = {69 00 70 00 63 00 68 00 6f 00 6f 00 6b 00 73 00 79 00 6e 00 63 00 [0-d0] 25 00 41 00 50 00 50 00 44 00 41 00 54 00 41 00 25 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 43 00 72 00 79 00 70 00 74 00 6f 00 5c 00 52 00 53 00 41 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}