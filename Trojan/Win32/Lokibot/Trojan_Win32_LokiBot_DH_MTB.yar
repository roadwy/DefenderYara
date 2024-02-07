
rule Trojan_Win32_LokiBot_DH_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {be 1a 58 c6 08 90 05 10 01 90 4e 75 90 00 } //01 00 
		$a_03_1 = {8b c6 03 c7 a3 90 01 04 a1 3c 9c 48 00 8a 98 90 01 04 8a 15 90 01 04 8b c3 e8 90 01 04 a2 90 01 04 90 05 10 01 90 8a 1d 90 01 04 90 05 10 01 90 a1 90 01 04 a3 90 01 04 8b c3 e8 90 01 04 90 05 10 01 90 a1 90 01 04 a3 90 01 04 90 05 10 01 90 a1 90 01 04 83 c0 02 a3 90 01 04 46 81 fe 90 01 04 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_LokiBot_DH_MTB_2{
	meta:
		description = "Trojan:Win32/LokiBot.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {24 65 65 61 34 65 63 36 64 2d 34 37 61 66 2d 34 65 31 35 2d 39 66 65 62 2d 35 38 39 31 63 36 62 61 62 37 32 63 } //01 00  $eea4ec6d-47af-4e15-9feb-5891c6bab72c
		$a_81_1 = {66 72 6d 42 61 73 65 53 46 } //01 00  frmBaseSF
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_5 = {41 63 74 69 76 61 74 6f 72 } //00 00  Activator
	condition:
		any of ($a_*)
 
}