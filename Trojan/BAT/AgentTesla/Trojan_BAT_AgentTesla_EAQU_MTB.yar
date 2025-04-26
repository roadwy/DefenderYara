
rule Trojan_BAT_AgentTesla_EAQU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EAQU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 08 11 04 18 6f 0b 00 00 0a 1f 10 28 0c 00 00 0a 6f 0d 00 00 0a 11 04 18 58 13 04 11 04 08 6f 0e 00 00 0a 32 da } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}