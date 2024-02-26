
rule Trojan_BAT_njRAT_RDZ_MTB{
	meta:
		description = "Trojan:BAT/njRAT.RDZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 66 68 68 6a } //01 00  gfhhj
		$a_01_1 = {61 30 65 70 36 61 31 35 48 75 48 62 43 71 42 7a } //01 00  a0ep6a15HuHbCqBz
		$a_01_2 = {61 38 59 46 79 52 45 43 4d 62 5a 79 } //00 00  a8YFyRECMbZy
	condition:
		any of ($a_*)
 
}