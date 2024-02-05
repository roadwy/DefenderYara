
rule Backdoor_Win32_Parcim_A{
	meta:
		description = "Backdoor:Win32/Parcim.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 08 00 08 00 00 02 00 "
		
	strings :
		$a_03_0 = {33 c9 83 fd 02 0f 9f c1 51 50 e8 90 01 04 83 c4 08 5d 68 b8 0b 00 00 ff 15 90 01 04 eb f3 90 00 } //02 00 
		$a_01_1 = {7e 14 8b 4c 24 04 53 8a 1c 08 80 f3 87 88 1c 08 40 3b c2 7c f2 } //02 00 
		$a_03_2 = {68 50 c3 00 00 50 ff 15 90 01 04 3d 02 01 00 00 75 3c 90 00 } //01 00 
		$a_01_3 = {53 76 63 48 6f 73 74 44 4c 4c 2e 65 78 65 00 } //01 00 
		$a_01_4 = {63 70 61 72 00 00 00 00 6d 5f } //01 00 
		$a_01_5 = {6d 5f 4d 61 69 6e 55 72 6c 00 } //01 00 
		$a_01_6 = {6d 5f 42 61 63 6b 55 72 6c 00 } //01 00 
		$a_01_7 = {6d 5f 44 6c 6c 4e 61 6d 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}