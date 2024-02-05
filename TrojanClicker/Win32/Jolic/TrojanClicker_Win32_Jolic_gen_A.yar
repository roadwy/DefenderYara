
rule TrojanClicker_Win32_Jolic_gen_A{
	meta:
		description = "TrojanClicker:Win32/Jolic.gen!A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 74 70 6c 00 75 } //01 00 
		$a_01_1 = {3d 70 61 67 65 75 } //01 00 
		$a_01_2 = {3d 72 65 71 00 75 } //01 00 
		$a_01_3 = {3d 75 70 64 00 75 } //00 00 
	condition:
		any of ($a_*)
 
}