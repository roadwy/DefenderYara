
rule Worm_Win32_Rebhip_X{
	meta:
		description = "Worm:Win32/Rebhip.X,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {78 5f 58 5f 42 4c 4f 43 4b 4d 4f 55 53 45 } //01 00  x_X_BLOCKMOUSE
		$a_01_1 = {5f 78 5f 58 5f 50 41 53 53 57 4f 52 44 } //01 00  _x_X_PASSWORD
		$a_01_2 = {23 23 23 23 40 23 23 23 23 20 23 23 23 } //01 00  ####@#### ###
		$a_01_3 = {55 6e 69 74 43 6f 6d 61 6e 64 6f 73 } //01 00  UnitComandos
		$a_01_4 = {43 47 2d 43 47 2d 43 47 2d 43 47 } //01 00  CG-CG-CG-CG
		$a_01_5 = {58 58 2d 58 58 2d 58 58 2d 58 58 } //00 00  XX-XX-XX-XX
		$a_00_6 = {5d 04 00 } //00 e3 
	condition:
		any of ($a_*)
 
}