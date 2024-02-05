
rule Worm_Win32_FoxBlade_E_dha{
	meta:
		description = "Worm:Win32/FoxBlade.E!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {5d 6a 41 58 6a 44 66 89 45 f0 8d 55 f0 58 6a 4d 8b 4e 08 66 89 45 f2 58 6a 49 66 89 45 f4 58 6a 4e 66 89 45 f6 } //01 00 
		$a_00_1 = {63 00 25 00 30 00 32 00 58 00 25 00 30 00 32 00 58 00 25 00 30 00 32 00 58 00 25 00 30 00 32 00 58 00 25 00 30 00 32 00 58 00 25 00 30 00 32 00 58 00 } //00 00 
	condition:
		any of ($a_*)
 
}