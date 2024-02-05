
rule Backdoor_Win32_Haxdoor_gen_C{
	meta:
		description = "Backdoor:Win32/Haxdoor.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 07 00 00 03 00 "
		
	strings :
		$a_01_0 = {68 6f 70 65 6e 59 5a ff e2 } //03 00 
		$a_03_1 = {51 83 04 24 04 90 09 05 00 b9 90 00 } //02 00 
		$a_01_2 = {c0 06 03 46 e2 fa } //01 00 
		$a_01_3 = {89 06 e3 14 8b 45 3c 8d 44 28 14 0f b7 10 8d 44 02 04 2b 48 0c 03 48 14 89 4e 04 83 c7 04 83 c6 08 eb d2 } //01 00 
		$a_01_4 = {8b 10 0b d2 74 09 80 3a b8 75 04 8b 42 01 } //01 00 
		$a_01_5 = {16 99 98 45 75 9e e0 dd } //01 00 
		$a_01_6 = {89 53 be af 9b 4a aa e3 } //00 00 
	condition:
		any of ($a_*)
 
}