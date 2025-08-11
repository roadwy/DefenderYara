
rule Trojan_BAT_AgentTesla_CE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 02 16 73 10 00 00 0a 13 0e 20 02 00 00 00 38 d2 ff ff ff 11 02 11 0b 16 11 0b 8e 69 6f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}