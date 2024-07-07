
rule Trojan_BAT_AgentTesla_PTJV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTJV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {7e 04 00 00 04 28 90 01 01 00 00 0a 02 6f 25 00 00 0a 6f 26 00 00 0a 0a 7e 03 00 00 04 06 25 0b 6f 27 00 00 0a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}