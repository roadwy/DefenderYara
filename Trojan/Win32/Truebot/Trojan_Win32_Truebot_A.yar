
rule Trojan_Win32_Truebot_A{
	meta:
		description = "Trojan:Win32/Truebot.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 6a 4c ff d6 8b d8 6a 4d 89 5d d4 ff d6 6a 4e 89 45 e8 ff d6 8b f8 6a 4f 89 7d d0 ff d6 } //01 00 
		$a_01_1 = {5c 5c 2e 5c 70 69 70 65 5c 7b 37 33 46 37 39 37 35 41 2d 41 34 41 32 2d 34 41 42 36 2d 39 31 32 31 2d 41 45 43 41 45 36 38 41 41 42 42 42 7d } //01 00 
		$a_01_2 = {5c 53 63 72 65 65 6e 4d 6f 6e 69 74 6f 72 53 65 72 76 69 63 65 5c } //00 00 
		$a_00_3 = {78 a0 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Truebot_A_2{
	meta:
		description = "Trojan:Win32/Truebot.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 9b 00 00 00 00 8d 88 90 01 04 03 ce 81 f9 cc b8 00 00 73 72 8a 88 90 01 04 30 8c 10 90 01 04 8d 4a 01 03 c8 81 f9 cc b8 00 00 73 57 8a 88 90 01 04 30 8c 10 90 01 04 8d 4a 02 03 c8 81 f9 cc b8 00 00 90 00 } //01 00 
		$a_03_1 = {5c 6d 73 73 2e 74 78 74 90 02 10 5c 6d 73 73 2e 65 78 65 90 00 } //01 00 
		$a_01_2 = {5c 5c 2e 5c 70 69 70 65 5c 7b 37 33 46 37 39 37 35 41 2d 41 34 41 32 2d 34 41 42 36 2d 39 31 32 31 2d 41 45 43 41 45 36 38 41 41 42 42 42 7d } //00 00 
		$a_00_3 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}