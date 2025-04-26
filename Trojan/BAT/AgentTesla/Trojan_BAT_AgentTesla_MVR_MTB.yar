
rule Trojan_BAT_AgentTesla_MVR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MVR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 7b 3e 00 00 04 16 02 7b 41 00 00 04 02 7b 3e 00 00 04 8e 69 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}