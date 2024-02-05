
rule Trojan_Win32_Tracur_Y{
	meta:
		description = "Trojan:Win32/Tracur.Y,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 44 24 0c 8a 11 03 c7 30 10 41 80 39 00 75 02 8b ce 47 3b 7c 24 10 72 e7 } //01 00 
		$a_03_1 = {8a 04 0a 32 87 90 01 04 47 3b 7d ec 88 01 7c 02 33 ff 41 ff 4d fc 75 e7 90 00 } //01 00 
		$a_03_2 = {89 5d f0 c7 45 e4 04 00 00 00 89 5d e8 ff 15 90 01 04 85 c0 74 19 81 7d f0 c8 00 00 00 74 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}