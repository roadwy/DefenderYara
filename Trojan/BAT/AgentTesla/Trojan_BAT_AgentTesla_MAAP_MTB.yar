
rule Trojan_BAT_AgentTesla_MAAP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MAAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 0a 0a 06 18 6f 90 01 01 00 00 0a 00 06 18 6f 90 01 01 00 00 0a 00 06 7e 90 01 01 00 00 04 6f 90 01 01 00 00 0a 00 06 6f 90 01 01 00 00 0a 02 16 02 8e 69 6f 90 01 01 00 00 0a 0b 2b 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}