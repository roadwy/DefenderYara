
rule Trojan_BAT_Injuke_GNE_MTB{
	meta:
		description = "Trojan:BAT/Injuke.GNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 5f 62 35 39 35 65 64 64 34 33 64 33 35 34 30 65 35 38 62 38 35 66 37 30 38 38 65 30 35 32 36 34 35 } //01 00  m_b595edd43d3540e58b85f7088e052645
		$a_01_1 = {66 38 44 42 44 36 37 42 37 34 39 35 44 46 30 33 } //01 00  f8DBD67B7495DF03
		$a_01_2 = {47 6f 70 6a 72 65 67 } //01 00  Gopjreg
		$a_80_3 = {47 68 76 69 68 6f 76 6e 2e 47 70 69 6c 63 78 72 77 } //Ghvihovn.Gpilcxrw  01 00 
		$a_80_4 = {44 6f 65 62 63 61 78 } //Doebcax  00 00 
	condition:
		any of ($a_*)
 
}