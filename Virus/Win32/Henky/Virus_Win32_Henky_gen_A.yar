
rule Virus_Win32_Henky_gen_A{
	meta:
		description = "Virus:Win32/Henky.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,ffffffc9 00 ffffffc9 00 03 00 00 64 00 "
		
	strings :
		$a_02_0 = {43 4f 44 45 44 90 02 08 42 59 90 02 08 48 65 6e 4b 79 90 00 } //64 00 
		$a_00_1 = {56 49 52 55 53 } //01 00  VIRUS
		$a_03_2 = {8b 04 24 66 33 c0 80 38 4d 74 90 01 01 2d 00 10 00 00 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}