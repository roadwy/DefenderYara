
rule Worm_Win32_Psyokym_B{
	meta:
		description = "Worm:Win32/Psyokym.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 79 20 59 50 53 20 20 2d 20 4b 65 79 4c 6f 67 67 65 72 00 } //01 00 
		$a_00_1 = {2f 00 65 00 78 00 74 00 72 00 61 00 63 00 74 00 2e 00 70 00 68 00 70 00 3f 00 78 00 3d 00 } //01 00  /extract.php?x=
		$a_00_2 = {61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 } //00 00  autorun.inf
	condition:
		any of ($a_*)
 
}