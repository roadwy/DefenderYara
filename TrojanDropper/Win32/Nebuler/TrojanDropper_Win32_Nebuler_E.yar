
rule TrojanDropper_Win32_Nebuler_E{
	meta:
		description = "TrojanDropper:Win32/Nebuler.E,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 09 00 "
		
	strings :
		$a_03_0 = {8b 51 08 ff d2 89 45 90 01 01 8b 45 08 05 90 01 04 50 8b 4d 90 01 01 51 8b 55 08 8b 42 04 ff d0 90 00 } //01 00 
		$a_01_1 = {8b 55 ec 3b 15 00 70 40 00 } //01 00 
		$a_01_2 = {8b 4d ec 3b 0d 00 70 40 00 } //01 00 
		$a_01_3 = {8b 45 ec 3b 05 00 70 40 00 } //01 00 
		$a_01_4 = {8b 45 ec 8a 88 00 70 40 00 } //01 00 
		$a_01_5 = {8b 4d ec 8a 91 00 70 40 00 } //01 00 
		$a_01_6 = {8b 55 ec 8a 82 00 70 40 00 } //01 00 
		$a_01_7 = {0f b6 91 00 70 40 00 33 d0 } //01 00 
		$a_01_8 = {0f b6 88 00 70 40 00 33 ca } //01 00 
		$a_01_9 = {0f b6 82 00 70 40 00 33 c1 } //00 00 
	condition:
		any of ($a_*)
 
}