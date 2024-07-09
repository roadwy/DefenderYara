
rule Trojan_BAT_AgentTesla_AMAL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 11 08 08 5d 13 09 11 08 09 5d 13 0a 06 11 09 91 13 0b 07 11 0a 6f ?? 00 00 0a 13 0c 02 06 11 08 28 ?? 00 00 06 13 0d 02 11 0b 11 0c 11 0d 28 ?? 00 00 06 13 0e 06 11 09 11 0e 20 00 01 00 00 5d d2 9c 00 11 08 17 59 13 08 11 08 16 fe 04 16 fe 01 13 0f 11 0f 2d a8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}