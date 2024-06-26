
rule TrojanDropper_Win32_Sirefef_gen_D{
	meta:
		description = "TrojanDropper:Win32/Sirefef.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {e4 26 16 91 cc 1d 46 59 39 03 00 00 3c 77 cd 6b } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDropper_Win32_Sirefef_gen_D_2{
	meta:
		description = "TrojanDropper:Win32/Sirefef.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 64 00 "
		
	strings :
		$a_03_0 = {8b 45 f4 8b 4d 90 01 01 0f b7 04 41 ff 75 14 8b 4d 90 01 01 ff 75 10 8b 04 81 ff 75 0c 03 45 08 ff d0 90 00 } //01 00 
		$a_03_1 = {8b d6 03 ce 2b d0 8b 45 90 01 01 8b 90 03 01 01 5d 7d 90 1b 00 8a 8c 90 03 01 01 19 39 90 01 04 88 8c 02 90 00 } //01 00 
		$a_03_2 = {03 ce 8b d6 2b d0 8b 45 90 01 01 8b 90 03 01 01 5d 7d 90 1b 00 8a 8c 90 03 01 01 19 39 90 01 04 88 8c 02 90 00 } //01 00 
		$a_03_3 = {f7 f3 8b d6 2b d0 8b 45 90 01 01 8b 90 03 01 01 5d 7d 90 1b 00 8a 8c 90 03 01 01 19 39 90 01 04 88 8c 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}