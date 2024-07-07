
rule Trojan_BAT_AgentTesla_CAV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 6a 17 11 33 1f 1f 5f 62 6a 11 40 1f 73 95 6e 5f 2e 03 16 2b 01 17 17 59 11 40 20 39 0e 00 00 95 5f 11 40 20 ee 0f 00 00 95 61 58 13 43 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}