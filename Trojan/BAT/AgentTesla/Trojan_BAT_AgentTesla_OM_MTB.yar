
rule Trojan_BAT_AgentTesla_OM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.OM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {5d 17 d6 28 90 02 04 da 0d 06 09 28 90 02 04 28 90 02 04 28 90 02 04 0a 00 08 17 d6 0c 08 07 fe 90 01 01 16 fe 90 01 01 13 90 01 01 11 90 01 01 2d 90 09 07 00 08 03 6f 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}