
rule Trojan_BAT_RedLineStealer_MR_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 0a 73 31 01 00 0a 0b 06 72 a9 18 00 70 28 90 01 03 0a 6f 90 01 03 0a 0c 20 f4 01 00 00 28 90 01 03 0a 00 07 72 50 19 00 70 28 90 01 03 0a 6f 90 01 03 0a 0d 08 28 90 01 03 0a 72 fd 19 00 70 6f 90 01 03 0a 13 04 11 04 72 45 1a 00 70 6f 90 00 } //01 00 
		$a_81_1 = {54 6f 53 74 72 69 6e 67 } //01 00  ToString
		$a_81_2 = {53 6c 65 65 70 } //01 00  Sleep
		$a_81_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_81_4 = {53 74 72 52 65 76 65 72 73 65 } //01 00  StrReverse
		$a_81_5 = {49 6e 76 6f 6b 65 } //01 00  Invoke
		$a_81_6 = {67 65 74 5f 70 61 73 73 77 64 } //01 00  get_passwd
		$a_81_7 = {67 65 74 5f 6c 6f 67 69 6e } //01 00  get_login
		$a_81_8 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_9 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_10 = {67 65 74 5f 54 72 61 6e 73 61 63 74 69 6f 6e } //00 00  get_Transaction
	condition:
		any of ($a_*)
 
}