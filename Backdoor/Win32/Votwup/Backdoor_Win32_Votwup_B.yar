
rule Backdoor_Win32_Votwup_B{
	meta:
		description = "Backdoor:Win32/Votwup.B,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 08 00 00 03 00 "
		
	strings :
		$a_01_0 = {80 fb 3b 75 48 8d 45 f0 50 8b 45 f4 e8 } //03 00 
		$a_01_1 = {68 88 13 00 00 68 1c 80 00 00 56 6a 00 68 00 80 00 00 } //01 00 
		$a_00_2 = {3f 75 69 64 3d 00 } //01 00  甿摩=
		$a_00_3 = {64 64 31 00 } //01 00  摤1
		$a_00_4 = {75 70 64 00 } //01 00  灵d
		$a_01_5 = {80 78 03 79 75 46 } //01 00 
		$a_01_6 = {64 64 75 72 6c 00 } //01 00  摤牵l
		$a_01_7 = {64 64 74 6f 74 00 } //00 00  摤潴t
	condition:
		any of ($a_*)
 
}