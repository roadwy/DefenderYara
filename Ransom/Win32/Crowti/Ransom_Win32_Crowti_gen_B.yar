
rule Ransom_Win32_Crowti_gen_B{
	meta:
		description = "Ransom:Win32/Crowti.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 45 f0 7c c6 45 f1 25 c6 45 f2 64 c6 45 f3 7d } //01 00 
		$a_01_1 = {8b 4d f8 8b 55 f4 66 8b 44 4a 02 66 89 45 fc 8b 4d f8 8b 55 f4 8b 45 f8 8b 75 f4 66 8b 04 46 66 89 44 4a 02 8b 4d f8 8b 55 f4 66 8b 45 fc 66 89 04 4a 8b 4d f8 83 c1 01 89 4d f8 } //01 00 
		$a_01_2 = {48 45 4c 50 5f 44 45 43 52 59 50 54 2e } //00 00  HELP_DECRYPT.
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}