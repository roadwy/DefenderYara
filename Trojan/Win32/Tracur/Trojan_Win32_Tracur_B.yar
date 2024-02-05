
rule Trojan_Win32_Tracur_B{
	meta:
		description = "Trojan:Win32/Tracur.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {1b 4d f4 6a 08 68 00 68 c4 61 51 50 e8 } //01 00 
		$a_01_1 = {66 c7 46 1c 44 65 66 c7 46 1e 74 6f 66 c7 46 20 75 72 } //01 00 
		$a_03_2 = {68 b8 0b 00 00 ff 15 90 01 03 10 68 88 13 00 00 ff 74 24 08 6a 00 90 00 } //01 00 
		$a_03_3 = {39 54 24 10 8b f8 7e 1d 8b 44 24 0c 8d 0c 06 8a 82 90 01 03 10 30 01 42 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}