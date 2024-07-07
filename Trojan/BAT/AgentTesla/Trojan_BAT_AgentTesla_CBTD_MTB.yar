
rule Trojan_BAT_AgentTesla_CBTD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CBTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 11 04 18 6f 90 01 04 20 90 01 04 28 90 01 04 13 06 09 11 06 6f 90 01 04 00 11 04 18 58 13 04 00 11 04 08 6f 90 01 04 fe 04 13 07 11 07 2d ca 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}