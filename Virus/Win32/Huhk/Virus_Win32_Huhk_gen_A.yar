
rule Virus_Win32_Huhk_gen_A{
	meta:
		description = "Virus:Win32/Huhk.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {eb 12 8a 06 0a c0 74 06 38 d8 74 02 32 c3 88 07 47 46 e2 ee 8b c2 83 c2 08 83 3a 00 75 d7 5b 58 8d 88 90 01 02 00 00 ff e1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}