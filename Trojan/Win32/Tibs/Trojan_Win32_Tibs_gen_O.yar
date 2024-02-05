
rule Trojan_Win32_Tibs_gen_O{
	meta:
		description = "Trojan:Win32/Tibs.gen!O,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 03 00 "
		
	strings :
		$a_01_0 = {8d 18 43 81 3b 72 73 72 63 74 } //01 00 
		$a_01_1 = {66 c7 45 fc 63 74 c6 45 fe 00 60 8d 45 ec 50 } //01 00 
		$a_01_2 = {c7 45 f0 56 69 72 74 c7 45 f4 75 61 6c 41 } //01 00 
		$a_01_3 = {55 89 e5 83 ec 20 c7 45 e0 56 69 72 74 c7 45 e4 75 61 6c 41 } //01 00 
		$a_01_4 = {c7 45 fc 00 00 00 00 60 8b 75 08 03 76 3c 0f b7 56 06 4a } //01 00 
		$a_03_5 = {03 76 3c 0f b7 56 06 4a 90 09 0e 00 c7 85 90 01 02 ff ff 00 00 00 00 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}