
rule Worm_Win32_Passdown{
	meta:
		description = "Worm:Win32/Passdown,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 41 75 74 6f 72 75 6e 2e 69 6e 66 } //01 00 
		$a_03_1 = {4f 8d 4f 01 8a 47 01 47 84 c0 75 f8 a1 90 01 04 8b 15 90 01 04 89 07 a1 90 01 04 89 57 04 8a 15 90 01 04 89 47 08 8d 84 24 90 01 02 00 00 50 51 88 57 0c ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}