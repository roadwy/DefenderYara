
rule Backdoor_BAT_Remcos_MA_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 06 16 06 8e 69 28 90 01 03 0a 06 0b dd 03 00 00 00 26 de db 90 00 } //10
		$a_01_1 = {3a 00 2f 00 2f 00 62 00 72 00 69 00 61 00 6e 00 65 00 74 00 61 00 76 00 65 00 72 00 61 00 73 00 2e 00 62 00 79 00 65 00 74 00 68 00 6f 00 73 00 74 00 31 00 33 00 2e 00 63 00 6f 00 6d 00 } //2 ://brianetaveras.byethost13.com
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*2) >=12
 
}
rule Backdoor_BAT_Remcos_MA_MTB_2{
	meta:
		description = "Backdoor:BAT/Remcos.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 75 00 70 00 6c 00 6f 00 6f 00 64 00 65 00 72 00 2e 00 6e 00 65 00 74 00 } //1 https://www.uplooder.net
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_2 = {77 00 65 00 6e 00 65 00 72 00 2f 00 20 00 67 00 69 00 66 00 6e 00 6f 00 63 00 70 00 69 00 } //1 wener/ gifnocpi
		$a_01_3 = {65 00 73 00 61 00 65 00 6c 00 65 00 72 00 2f 00 20 00 67 00 69 00 66 00 6e 00 6f 00 63 00 70 00 69 00 } //1 esaeler/ gifnocpi
		$a_01_4 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_5 = {54 00 65 00 73 00 74 00 2d 00 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6f 00 6e 00 20 00 77 00 77 00 77 00 2e 00 67 00 6f 00 6f 00 67 00 6c 00 65 00 2e 00 63 00 6f 00 6d 00 } //1 Test-Connection www.google.com
		$a_01_6 = {75 00 73 00 65 00 72 00 3a 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 } //1 user:password
		$a_01_7 = {67 65 74 5f 47 65 74 42 79 74 65 73 } //1 get_GetBytes
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}