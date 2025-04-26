
rule Trojan_BAT_AgentTesla_SIFA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SIFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 20 16 70 01 00 0b 2b 1d 00 06 07 23 00 00 00 00 00 00 f0 40 28 ?? ?? ?? 0a 69 28 ?? ?? ?? 06 0a 00 07 15 58 0b 07 16 fe 04 16 fe 01 0c 08 2d d8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}