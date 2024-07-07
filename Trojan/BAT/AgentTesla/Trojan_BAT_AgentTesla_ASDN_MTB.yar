
rule Trojan_BAT_AgentTesla_ASDN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASDN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 07 08 11 07 91 11 04 61 09 11 06 91 61 28 90 01 01 00 00 0a 9c 11 06 1f 15 fe 01 13 09 11 09 2c 05 16 13 06 2b 06 11 06 17 58 13 06 11 07 17 58 13 07 00 11 07 08 8e 69 17 59 fe 02 16 fe 01 13 0a 11 0a 2d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}