
rule Backdoor_Win32_Escad_O_dha{
	meta:
		description = "Backdoor:Win32/Escad.O!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {8a 14 08 80 c2 90 01 01 80 f2 90 01 01 88 14 08 40 3b c6 7c ef 90 00 } //01 00 
		$a_01_1 = {b8 2d 2d 2d 2d 8d } //01 00 
		$a_00_2 = {3d 3d 3d 20 25 30 34 64 2e 25 30 32 64 2e 25 30 32 64 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64 20 3d 3d 3d } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Escad_O_dha_2{
	meta:
		description = "Backdoor:Win32/Escad.O!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {8a 14 08 80 c2 90 01 01 80 f2 90 01 01 88 14 08 40 3b c6 7c ef 90 00 } //01 00 
		$a_01_1 = {b8 2d 2d 2d 2d 8d } //01 00 
		$a_00_2 = {3d 3d 3d 20 25 30 34 64 2e 25 30 32 64 2e 25 30 32 64 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64 20 3d 3d 3d } //00 00 
		$a_00_3 = {5d 04 00 } //00 80 
	condition:
		any of ($a_*)
 
}