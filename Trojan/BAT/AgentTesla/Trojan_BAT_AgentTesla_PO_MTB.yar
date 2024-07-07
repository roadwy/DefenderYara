
rule Trojan_BAT_AgentTesla_PO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {9a 0b 02 07 90 01 0a 2a 90 09 12 00 28 90 01 09 0a 06 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}