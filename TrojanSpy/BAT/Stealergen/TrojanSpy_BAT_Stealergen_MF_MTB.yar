
rule TrojanSpy_BAT_Stealergen_MF_MTB{
	meta:
		description = "TrojanSpy:BAT/Stealergen.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 8e 69 1f 0f 59 8d 90 01 01 00 00 01 0b 02 1f 0f 07 16 02 8e 69 1f 0f 59 28 90 01 03 0a 1f 10 8d 90 01 01 00 00 01 0c 07 8e 69 08 8e 69 59 8d 90 01 01 00 00 01 0d 07 07 8e 69 1f 10 59 08 16 1f 10 28 90 01 03 0a 07 16 09 16 07 8e 69 08 8e 69 59 28 90 01 03 0a 73 90 01 03 06 13 04 28 90 01 03 0a 11 04 03 06 14 09 08 6f 90 01 03 06 6f 90 01 03 0a 13 05 de 90 00 } //01 00 
		$a_01_1 = {67 65 74 5f 55 73 65 72 4e 61 6d 65 } //01 00  get_UserName
		$a_01_2 = {67 65 74 5f 50 61 73 73 77 6f 72 64 } //01 00  get_Password
		$a_01_3 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_01_4 = {42 43 72 79 70 74 44 65 63 72 79 70 74 } //01 00  BCryptDecrypt
		$a_01_5 = {44 65 63 72 79 70 74 57 69 74 68 4b 65 79 } //01 00  DecryptWithKey
		$a_01_6 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_7 = {47 65 74 41 6c 6c 50 72 6f 66 69 6c 65 73 } //01 00  GetAllProfiles
		$a_01_8 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_9 = {67 65 74 5f 4b 65 79 } //00 00  get_Key
	condition:
		any of ($a_*)
 
}