
rule Trojan_BAT_AgentTesla_MBER_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {34 00 44 00 35 00 41 00 39 00 5f 00 5f 00 33 00 5f 00 5f 00 5f 00 30 00 34 00 5f 00 5f 00 5f 00 5b 00 5b 00 5b 00 5b 00 5f 00 5f 00 42 00 38 00 5f 00 5f 00 5f 00 5f 00 5f 00 5f 00 5f 00 34 00 5f 00 5f 00 5f 00 5f 00 5f 00 5f 00 5f 00 5f 00 5f 00 5f 00 5f 00 5f 00 5f 00 5f 00 5f 00 5f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}