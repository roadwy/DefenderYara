
rule Backdoor_Win32_Bedep_B_{
	meta:
		description = "Backdoor:Win32/Bedep.B!!Bedep.gen!B,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 07 00 00 02 00 "
		
	strings :
		$a_03_0 = {8a 45 fc 0f be 1e f6 ea 8a d3 2a d0 8b 45 fc 80 ea 90 01 01 46 88 11 c1 c8 08 01 45 fc 41 ff 4d 08 8b d3 75 dd 90 00 } //02 00 
		$a_01_1 = {33 5d 1c 69 db 65 9d 01 00 03 d9 33 d8 ff 4d f8 83 7d f8 00 7f ea 8b 4d 10 69 ff 83 02 00 00 } //01 00 
		$a_03_2 = {80 78 20 23 0f 85 90 01 04 80 78 31 23 0f 85 90 01 04 8d 44 08 ff 80 38 23 90 00 } //01 00 
		$a_03_3 = {85 c0 75 01 c3 59 8b 90 01 05 a9 01 00 00 00 74 0b 6a 00 83 f0 01 8b 90 01 05 50 51 ff e2 90 00 } //02 00 
		$a_03_4 = {b8 7b 00 00 c0 78 90 01 01 81 39 2a d8 12 1c 90 00 } //01 00 
		$a_01_5 = {5c 78 46 46 d2 41 b8 2b 00 00 00 45 8b 8d bc 00 00 00 41 8b a5 c8 00 00 00 41 8e d0 } //01 00 
		$a_01_6 = {c7 40 60 45 76 38 12 } //05 00 
	condition:
		any of ($a_*)
 
}