
rule Backdoor_Win32_Zegost_gen_C{
	meta:
		description = "Backdoor:Win32/Zegost.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff 2e c6 85 90 01 02 ff ff 70 c6 85 90 01 02 ff ff 62 90 00 } //01 00 
		$a_03_1 = {ff 5c c6 85 90 01 02 ff ff 74 c6 85 90 01 02 ff ff 63 90 00 } //01 00 
		$a_03_2 = {ff 2e c6 85 90 01 02 ff ff 64 c6 85 90 01 02 ff ff 6c 90 00 } //01 00 
		$a_03_3 = {ff 53 c6 85 90 01 02 ff ff 4f c6 85 90 01 02 ff ff 46 90 00 } //01 00 
		$a_03_4 = {ff 5c c6 85 90 01 02 ff ff 41 c6 85 90 01 02 ff ff 70 90 00 } //01 00 
		$a_03_5 = {ff 5c c6 85 90 01 02 ff ff 4d c6 85 90 01 02 ff ff 69 90 00 } //0a 00 
		$a_00_6 = {00 5b 43 61 70 73 4c 6f 63 6b 5d 00 } //0a 00 
		$a_00_7 = {57 69 6e 53 74 61 30 5c 44 65 66 61 75 6c 74 } //0a 00 
		$a_01_8 = {25 2d 32 34 73 20 25 2d 31 35 73 } //0a 00 
		$a_00_9 = {68 74 74 70 2f 31 2e 31 20 34 30 33 20 66 6f 72 62 69 64 64 65 6e } //0a 00 
		$a_00_10 = {70 62 6b 5c 72 61 73 70 68 6f 6e 65 2e 70 62 6b } //00 00 
	condition:
		any of ($a_*)
 
}