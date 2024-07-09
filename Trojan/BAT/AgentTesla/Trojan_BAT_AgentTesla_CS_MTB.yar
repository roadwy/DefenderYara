
rule Trojan_BAT_AgentTesla_CS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {20 00 10 00 00 8d ?? ?? ?? 01 0d 73 ?? ?? ?? 0a 0a 08 09 16 20 00 10 00 00 6f ?? ?? ?? 0a 0b 07 16 fe 02 13 05 11 05 2c 09 06 09 16 07 6f ?? ?? ?? 0a 07 16 fe 02 13 06 11 06 2d d5 06 6f ?? ?? ?? 0a 13 04 de 11 06 2c 06 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}