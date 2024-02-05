
rule Worm_Win32_Ganelp_C{
	meta:
		description = "Worm:Win32/Ganelp.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 64 3a 61 65 6c 2a 6e 45 3a 3a } //01 00 
		$a_01_1 = {67 46 73 6f 6d 65 72 61 6c 50 72 69 } //01 00 
		$a_01_2 = {53 61 45 67 56 65 65 74 75 41 52 65 6c 78 } //01 00 
		$a_03_3 = {03 4d fc 0f be 51 05 83 fa 73 75 90 01 01 a1 90 01 04 03 45 fc 0f be 48 08 83 f9 74 75 90 01 01 8b 90 01 05 03 55 fc 0f be 42 0c 83 f8 6e 75 90 01 01 8b 90 01 05 03 4d fc 0f be 51 0f 83 fa 77 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}