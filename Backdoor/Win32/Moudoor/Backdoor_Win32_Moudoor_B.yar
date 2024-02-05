
rule Backdoor_Win32_Moudoor_B{
	meta:
		description = "Backdoor:Win32/Moudoor.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c1 6a 06 99 5b f7 fb 80 c2 66 30 14 31 41 3b cf 72 ed 8d 45 } //01 00 
		$a_01_1 = {8b c1 6a 06 99 5b f7 fb 80 c2 66 30 14 39 41 3b 4d } //01 00 
		$a_01_2 = {75 70 2e 62 61 6b 00 00 55 70 64 61 74 65 57 69 6e 64 6f 77 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Moudoor_B_2{
	meta:
		description = "Backdoor:Win32/Moudoor.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {65 00 78 00 65 00 2e 00 79 00 61 00 72 00 74 00 65 00 78 00 6b 00 } //01 00 
		$a_01_1 = {6a 45 33 c0 59 8d bd e9 fe ff ff 88 9d e8 fe ff ff f3 ab 66 ab aa 8d 85 e8 fe ff ff c7 04 24 18 01 00 00 } //01 00 
		$a_03_2 = {8b fb 83 c9 ff 33 c0 f2 ae f7 d1 49 83 f9 06 0f 86 90 01 02 00 00 6a 3a 53 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}