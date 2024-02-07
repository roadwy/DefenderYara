
rule Trojan_BAT_SpySnake_MR_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {25 16 07 06 9a a2 25 17 1f 10 8c 4a 00 00 01 a2 6f 90 01 03 0a a5 06 00 00 01 9c 06 17 58 0a 06 07 8e 69 fe 04 13 08 11 08 2d ad 90 00 } //05 00 
		$a_01_1 = {63 38 39 65 63 30 31 33 2d 31 34 66 64 2d 34 32 38 31 2d 61 61 33 62 2d 64 64 34 36 30 35 64 33 32 37 35 66 } //01 00  c89ec013-14fd-4281-aa3b-dd4605d3275f
		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //00 00  InvokeMember
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_SpySnake_MR_MTB_2{
	meta:
		description = "Trojan:BAT/SpySnake.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {0d 00 2b 1f 09 20 e5 8e fb 0e fe 01 13 1a 11 1a 2c 09 20 1c 8f fb 0e 0d 00 2b 08 00 20 01 8f fb 0e 0d 00 } //02 00 
		$a_03_1 = {50 45 00 00 4c 01 03 00 90 01 04 00 00 00 00 00 00 00 00 e0 00 02 01 0b 01 50 90 00 } //02 00 
		$a_01_2 = {53 74 72 52 65 76 65 72 73 65 } //02 00  StrReverse
		$a_01_3 = {43 72 65 61 74 65 5f 5f 49 6e 73 74 61 6e 63 65 5f 5f } //00 00  Create__Instance__
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_SpySnake_MR_MTB_3{
	meta:
		description = "Trojan:BAT/SpySnake.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 28 90 01 03 0a 03 6f 90 01 03 0a 6f 90 01 03 0a 0a 7e 90 01 01 00 00 04 06 6f 90 01 03 0a 00 7e 90 01 01 00 00 04 18 6f 90 01 03 0a 00 7e 90 01 01 00 00 04 6f 90 01 03 0a 80 90 01 01 00 00 04 02 28 90 01 03 06 0c 08 0d 7e 90 01 01 00 00 04 6f 90 01 03 0a 00 09 13 04 2b 00 11 04 2a 90 00 } //01 00 
		$a_01_1 = {48 61 73 68 50 61 73 73 77 6f 72 64 46 6f 72 53 74 6f 72 69 6e 67 49 6e 43 6f 6e 66 69 67 46 69 6c 65 } //01 00  HashPasswordForStoringInConfigFile
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_4 = {43 61 6c 7a 6f 6e 65 } //01 00  Calzone
		$a_01_5 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_01_6 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  TransformFinalBlock
		$a_01_7 = {47 65 74 44 6f 6d 61 69 6e } //01 00  GetDomain
		$a_01_8 = {73 65 74 5f 4b 65 79 } //00 00  set_Key
	condition:
		any of ($a_*)
 
}