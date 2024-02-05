
rule Virus_WinNT_Cutwail_gen_C{
	meta:
		description = "Virus:WinNT/Cutwail.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {85 c9 74 09 30 06 46 c1 c0 03 49 eb f3 } //01 00 
		$a_03_1 = {68 da 84 ae 28 68 28 5f c3 d0 8b 45 fc 50 e8 90 01 04 a3 90 01 04 68 e8 d8 02 9a 68 5d 33 78 df 90 00 } //01 00 
		$a_01_2 = {89 45 e4 68 52 57 4e 44 8b 55 e4 52 8b 45 14 50 ff 15 } //01 00 
	condition:
		any of ($a_*)
 
}