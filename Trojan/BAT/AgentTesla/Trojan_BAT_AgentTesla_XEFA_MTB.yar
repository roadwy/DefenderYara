
rule Trojan_BAT_AgentTesla_XEFA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.XEFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 16 fc 00 00 0c 2b 16 7e 90 01 03 04 07 08 20 00 01 00 00 28 90 01 03 06 0b 08 15 58 0c 08 16 fe 04 16 fe 01 0d 09 2d df 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}