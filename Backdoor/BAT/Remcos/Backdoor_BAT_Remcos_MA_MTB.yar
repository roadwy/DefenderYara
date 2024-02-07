
rule Backdoor_BAT_Remcos_MA_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 75 00 70 00 6c 00 6f 00 6f 00 64 00 65 00 72 00 2e 00 6e 00 65 00 74 00 } //01 00  https://www.uplooder.net
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_01_2 = {77 00 65 00 6e 00 65 00 72 00 2f 00 20 00 67 00 69 00 66 00 6e 00 6f 00 63 00 70 00 69 00 } //01 00  wener/ gifnocpi
		$a_01_3 = {65 00 73 00 61 00 65 00 6c 00 65 00 72 00 2f 00 20 00 67 00 69 00 66 00 6e 00 6f 00 63 00 70 00 69 00 } //01 00  esaeler/ gifnocpi
		$a_01_4 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_01_5 = {54 00 65 00 73 00 74 00 2d 00 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6f 00 6e 00 20 00 77 00 77 00 77 00 2e 00 67 00 6f 00 6f 00 67 00 6c 00 65 00 2e 00 63 00 6f 00 6d 00 } //01 00  Test-Connection www.google.com
		$a_01_6 = {75 00 73 00 65 00 72 00 3a 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 } //01 00  user:password
		$a_01_7 = {67 65 74 5f 47 65 74 42 79 74 65 73 } //00 00  get_GetBytes
	condition:
		any of ($a_*)
 
}