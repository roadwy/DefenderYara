
rule Trojan_BAT_AgentTesla_MBJD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBJD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 06 8e 69 5d 13 05 07 11 04 6f ?? 00 00 0a 5d 13 08 06 11 05 91 13 09 11 04 11 08 6f ?? 00 00 0a 13 0a 02 06 07 28 ?? 00 00 06 13 0b 02 11 09 11 0a 11 0b 28 ?? 00 00 06 13 0c 06 11 05 11 0c 20 00 01 00 00 5d d2 9c 07 17 59 0b 07 16 fe 04 16 fe 01 13 0d 11 0d 2d a7 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}