
rule Trojan_BAT_AgentTesla_MBHT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBHT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {35 00 53 00 30 00 37 00 52 00 53 00 47 00 47 00 38 00 5a 00 43 00 34 00 38 00 38 00 57 00 34 00 41 00 39 00 35 00 35 00 41 00 54 00 } //1 5S07RSGG8ZC488W4A955AT
	condition:
		((#a_01_0  & 1)*1) >=1
 
}