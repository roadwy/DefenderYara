
rule Trojan_BAT_njRAT_RDZ_MTB{
	meta:
		description = "Trojan:BAT/njRAT.RDZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {67 66 68 68 6a } //1 gfhhj
		$a_01_1 = {61 30 65 70 36 61 31 35 48 75 48 62 43 71 42 7a } //1 a0ep6a15HuHbCqBz
		$a_01_2 = {61 38 59 46 79 52 45 43 4d 62 5a 79 } //1 a8YFyRECMbZy
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}