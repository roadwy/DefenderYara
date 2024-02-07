
rule Trojan_BAT_SpySnake_MAA_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_03_0 = {0b 07 0c 2b 00 08 2a 90 0a 3f 00 7e 90 01 03 04 28 90 01 03 0a 03 6f 90 01 03 0a 6f 90 01 03 0a 0a 7e 90 01 03 04 06 6f 90 01 03 0a 00 7e 90 01 03 04 18 6f 90 01 03 0a 00 02 28 90 01 03 06 90 00 } //01 00 
		$a_01_1 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_01_2 = {53 68 6f 77 50 61 73 73 77 6f 72 64 5f 4d 6f 75 73 65 44 6f 77 6e } //01 00  ShowPassword_MouseDown
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_01_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_5 = {74 78 74 50 61 73 73 77 6f 72 64 5f 54 65 78 74 43 68 61 6e 67 65 64 } //01 00  txtPassword_TextChanged
		$a_01_6 = {74 78 74 4e 61 6d 65 5f 4b 65 79 50 72 65 73 73 } //01 00  txtName_KeyPress
		$a_01_7 = {43 72 65 64 69 74 43 61 72 64 5f 43 68 65 63 6b 65 64 43 68 61 6e 67 65 64 } //01 00  CreditCard_CheckedChanged
		$a_01_8 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //00 00  TransformFinalBlock
	condition:
		any of ($a_*)
 
}