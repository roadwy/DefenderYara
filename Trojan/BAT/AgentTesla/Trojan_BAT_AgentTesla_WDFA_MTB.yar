
rule Trojan_BAT_AgentTesla_WDFA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.WDFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {fe 0c 04 00 fe 0c 06 00 fe 0c 04 00 fe 0c 06 00 91 fe 0c 06 00 61 d2 9c fe 0c 06 00 20 01 00 00 00 58 fe 0e 06 00 fe 0c 06 00 fe 0c 04 00 8e 69 3f cb ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}