
rule Backdoor_Win32_Afcore_gen_B{
	meta:
		description = "Backdoor:Win32/Afcore.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 04 00 "
		
	strings :
		$a_01_0 = {74 16 6a 01 57 ff 56 34 33 c9 3b c1 74 06 51 53 51 51 ff d0 57 ff 56 30 } //03 00 
		$a_03_1 = {68 00 30 10 00 ff 90 17 03 01 01 01 33 36 37 90 00 } //01 00 
		$a_03_2 = {ff d0 68 00 80 00 00 6a 00 ff 35 90 01 03 10 ff 55 90 01 04 8a 45 90 01 01 c9 90 00 } //01 00 
		$a_03_3 = {30 40 00 ff 55 90 01 01 6a 00 ff 15 90 01 01 20 40 00 90 09 0c 00 ff 90 01 01 68 00 80 00 00 6a 00 ff 35 90 00 } //01 00 
		$a_03_4 = {8b d1 83 e2 03 02 44 15 90 01 01 30 81 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}