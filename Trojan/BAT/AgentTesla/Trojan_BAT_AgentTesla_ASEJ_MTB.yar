
rule Trojan_BAT_AgentTesla_ASEJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASEJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 07 11 12 28 ?? 00 00 06 13 17 02 11 15 11 16 11 17 28 ?? 00 00 06 13 18 } //1
		$a_01_1 = {11 12 07 8e 69 5d } //1
		$a_01_2 = {47 00 56 00 5a 00 54 00 41 00 38 00 35 00 47 00 35 00 41 00 41 00 43 00 47 00 53 00 34 00 37 00 34 00 35 00 52 00 38 00 49 00 48 00 } //2 GVZTA85G5AACGS4745R8IH
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=4
 
}