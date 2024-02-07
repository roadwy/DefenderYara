
rule Worm_Win32_Esfury_gen_A{
	meta:
		description = "Worm:Win32/Esfury.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 00 68 00 65 00 61 00 70 00 73 00 31 00 2e 00 69 00 6e 00 66 00 6f 00 2f 00 00 00 } //01 00 
		$a_01_1 = {61 00 63 00 74 00 69 00 6f 00 6e 00 3d 00 41 00 62 00 72 00 69 00 72 00 } //01 00  action=Abrir
		$a_01_2 = {6d 53 70 72 65 61 64 5f 41 75 74 6f 72 75 6e } //01 00  mSpread_Autorun
		$a_01_3 = {6d 53 70 72 65 61 64 5f 4d 73 6e } //00 00  mSpread_Msn
	condition:
		any of ($a_*)
 
}