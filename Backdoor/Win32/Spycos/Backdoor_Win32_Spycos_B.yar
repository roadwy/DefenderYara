
rule Backdoor_Win32_Spycos_B{
	meta:
		description = "Backdoor:Win32/Spycos.B,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 01 00 08 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 73 20 8d 55 fc b8 90 01 04 e8 90 01 04 8b 45 fc e8 90 01 04 50 e8 90 01 04 a3 90 01 04 33 c0 5a 90 00 } //01 00 
		$a_03_1 = {01 73 22 8d 4d fc 33 d2 b8 90 01 04 e8 90 01 04 8b 45 fc e8 90 01 04 50 e8 90 01 04 a3 90 01 04 33 c0 5a 90 00 } //0a 00 
		$a_01_2 = {c7 46 04 bf a9 00 00 68 } //0a 00 
		$a_01_3 = {c7 46 04 50 fc 0b 00 68 } //0a 00 
		$a_03_4 = {89 45 e0 8d 55 94 b8 90 01 04 e8 90 01 03 ff 8b 55 94 8b 4d e0 8b c3 8b 30 ff 56 4c 8b c3 90 00 } //0a 00 
		$a_03_5 = {75 6a 8d 95 5c fe ff ff b8 90 01 04 e8 90 01 03 ff 8b 85 5c fe ff ff e8 90 01 03 ff 33 c9 b2 01 90 09 0a 00 50 6a 00 e8 90 01 03 ff 85 c0 90 00 } //0a 00 
		$a_03_6 = {83 3e 00 75 0a 68 88 13 00 00 e8 90 01 03 ff 43 83 fb 0a 7f 09 83 3e 00 0f 84 b8 fe ff ff 90 00 } //0a 00 
		$a_00_7 = {43 83 fb 29 0f 85 79 ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}