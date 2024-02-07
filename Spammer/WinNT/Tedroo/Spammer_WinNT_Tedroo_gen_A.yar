
rule Spammer_WinNT_Tedroo_gen_A{
	meta:
		description = "Spammer:WinNT/Tedroo.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 2c 8b 45 1c 8b 40 10 0f be 00 83 f8 34 75 0b } //01 00 
		$a_01_1 = {83 7d f8 26 74 18 eb 40 8b 45 08 8b 40 3c 89 45 fc eb 35 } //01 00 
		$a_03_2 = {c6 40 06 68 a1 90 01 04 c7 40 07 90 01 04 a1 90 01 04 c6 40 0b c3 90 00 } //01 00 
		$a_01_3 = {69 64 3d 25 73 26 73 6d 74 70 3d } //00 00  id=%s&smtp=
	condition:
		any of ($a_*)
 
}