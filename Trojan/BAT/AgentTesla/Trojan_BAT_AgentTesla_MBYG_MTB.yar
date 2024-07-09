
rule Trojan_BAT_AgentTesla_MBYG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBYG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {11 05 11 04 91 11 11 61 11 05 11 12 91 59 13 } //1
		$a_03_1 = {13 0f 09 20 ?? 00 00 00 91 20 ?? 00 00 00 59 0a } //1
		$a_01_2 = {02 58 05 59 d2 61 d2 81 } //1
		$a_03_3 = {13 07 06 20 ?? 00 00 00 91 06 1f ?? 91 59 0c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}