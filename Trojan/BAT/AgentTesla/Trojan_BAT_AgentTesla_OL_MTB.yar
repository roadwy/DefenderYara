
rule Trojan_BAT_AgentTesla_OL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.OL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0b 17 0c 2b 90 02 02 02 08 28 90 01 04 03 08 03 6f 90 01 04 5d 17 d6 28 90 01 04 da 0d 06 09 28 90 01 04 28 90 01 04 28 90 01 04 0a 00 08 17 d6 0c 08 07 fe 90 01 01 16 fe 90 01 01 13 90 01 01 11 90 01 01 2d 90 01 01 06 13 90 01 01 2b 90 01 01 11 90 01 01 2a 90 09 0c 00 72 90 01 04 0a 02 6f 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}