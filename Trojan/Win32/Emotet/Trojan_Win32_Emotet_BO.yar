
rule Trojan_Win32_Emotet_BO{
	meta:
		description = "Trojan:Win32/Emotet.BO,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 65 23 40 31 2e 50 64 62 } //03 00  he#@1.Pdb
		$a_03_1 = {8b 44 24 18 89 c1 83 e0 90 01 01 8a 90 01 05 c7 44 24 90 01 05 c7 44 24 90 01 05 8b 44 24 90 01 01 8a 34 08 28 d6 8b 74 24 90 01 01 88 34 0e 83 c1 90 01 01 89 4c 24 90 01 01 8b 7c 24 90 01 01 39 f9 74 90 00 } //00 00 
		$a_00_2 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}