
rule Trojan_BAT_AgentTesla_CSWL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CSWL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 06 11 07 6f 90 01 04 0d 00 06 09 6f 90 01 04 13 04 11 04 1a 28 90 01 04 fe 04 1e 28 90 01 04 fe 01 13 08 11 08 2d 0c 00 08 09 6f 90 01 04 26 00 2b 25 00 11 04 07 59 06 6f 90 01 04 58 06 6f 90 01 04 5d 13 04 08 06 11 04 6f 90 01 04 6f 90 01 04 26 00 00 11 07 1f 0c 28 90 01 04 58 13 07 11 07 11 06 6f 90 01 04 fe 04 13 08 11 08 3a 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}