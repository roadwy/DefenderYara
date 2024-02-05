
rule Worm_Win32_Morto_gen_A{
	meta:
		description = "Worm:Win32/Morto.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {75 0c 46 46 47 47 84 90 01 01 75 e2 90 09 19 00 90 02 12 75 1a 84 90 01 01 74 12 8a 90 00 } //02 00 
		$a_01_1 = {64 a1 30 00 00 00 89 45 fc 8b 45 fc 8b 40 0c 8b 78 10 8b 70 0c 3b f7 74 1f } //01 00 
		$a_01_2 = {eb 24 3c 41 7c 0f 3c 5a 7f 0b 0f be c0 8a } //01 00 
		$a_03_3 = {53 59 53 54 c7 45 90 01 01 45 4d 5c 57 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}