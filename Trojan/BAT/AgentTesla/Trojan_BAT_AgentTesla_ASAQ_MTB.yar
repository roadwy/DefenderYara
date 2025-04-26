
rule Trojan_BAT_AgentTesla_ASAQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 04 09 6f ?? 00 00 0a 11 04 18 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 07 16 07 8e 69 6f ?? 00 00 0a 13 05 } //3
		$a_01_1 = {35 00 38 00 39 00 38 00 43 00 32 00 59 00 45 00 35 00 53 00 34 00 42 00 34 00 50 00 42 00 42 00 38 00 45 00 34 00 43 00 34 00 35 00 } //2 5898C2YE5S4B4PBB8E4C45
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}