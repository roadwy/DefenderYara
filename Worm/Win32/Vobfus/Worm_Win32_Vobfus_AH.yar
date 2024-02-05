
rule Worm_Win32_Vobfus_AH{
	meta:
		description = "Worm:Win32/Vobfus.AH,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {54 ff fd b6 90 01 01 00 00 90 02 10 8e 76 90 01 01 00 1b 90 01 02 2a 23 90 01 02 1b 90 01 02 2a 23 90 01 02 1b 90 01 02 2a 23 90 01 02 1b 90 01 02 2a 23 90 01 02 1b 90 01 02 2a 23 90 01 02 1b 90 01 02 2a 23 90 01 02 1b 90 01 02 2a 23 90 00 } //01 00 
		$a_00_1 = {63 00 00 00 02 00 00 00 6f 00 00 00 02 00 00 00 64 00 00 00 02 00 00 00 65 00 00 00 } //01 00 
		$a_02_2 = {2e 00 00 00 02 00 00 00 62 00 00 00 90 02 08 02 00 00 00 70 00 00 00 02 00 00 00 61 00 00 00 90 00 } //01 00 
		$a_00_3 = {7a 00 00 00 02 00 00 00 20 00 00 00 02 00 00 00 31 00 00 00 02 00 00 00 63 00 00 00 } //01 00 
		$a_02_4 = {47 00 00 00 90 02 08 02 00 00 00 4d 00 00 00 02 00 00 00 46 00 00 00 02 00 00 00 4e 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}