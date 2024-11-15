
rule Trojan_BAT_AgentTesla_PHPH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PHPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 06 07 6f ?? ?? ?? 0a 0c 04 03 6f ?? ?? ?? 0a 59 0d 09 19 fe 04 16 fe 01 13 05 11 05 2c 2f 00 03 19 8d 8f 00 00 01 25 16 12 02 28 ?? ?? ?? 0a 9c 25 17 12 02 28 ?? ?? ?? 0a 9c 25 18 12 02 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}