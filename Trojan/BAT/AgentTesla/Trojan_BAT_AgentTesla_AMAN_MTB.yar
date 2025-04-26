
rule Trojan_BAT_AgentTesla_AMAN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 06 03 8e 69 5d 0b 06 04 6f ?? 00 00 0a 5d 0c 03 07 91 0d 04 08 6f ?? 00 00 0a 13 04 02 03 06 28 ?? 00 00 06 13 05 02 09 11 04 11 05 28 ?? 00 00 06 13 06 03 07 11 06 20 00 01 00 00 5d d2 9c 00 06 17 59 0a 06 16 fe 04 16 fe 01 13 07 11 07 2d ae } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}