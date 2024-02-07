
rule Trojan_BAT_Bladabindi_NEAB_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.NEAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {28 0e 00 00 0a 6f a3 00 00 0a 06 07 6f a4 00 00 0a 17 73 96 00 00 0a 25 02 16 02 8e 69 6f a5 00 00 0a 6f a6 00 00 0a 06 28 5e 00 00 06 28 1a 01 00 06 2a } //02 00 
		$a_01_1 = {42 61 73 65 64 41 6e 74 69 56 54 2e 65 78 65 } //02 00  BasedAntiVT.exe
		$a_01_2 = {6d 5f 66 35 66 35 36 39 38 62 31 64 66 30 34 66 62 32 61 35 39 62 32 66 65 62 32 30 38 36 65 33 63 37 } //00 00  m_f5f5698b1df04fb2a59b2feb2086e3c7
	condition:
		any of ($a_*)
 
}