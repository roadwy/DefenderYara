
rule Trojan_BAT_AgentTesla_AANV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AANV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 1b 11 04 5d 13 1c 11 1b 11 05 5d 13 1d 08 11 1c 91 13 1e 09 11 1d 6f ?? 00 00 0a 13 1f 08 11 1b 17 58 11 04 5d 91 13 20 11 1e 11 1f 61 11 20 59 20 00 01 00 00 58 13 21 08 11 1c 11 21 20 00 01 00 00 5d d2 9c 00 11 1b 17 59 13 1b 11 1b 16 fe 04 16 fe 01 13 22 11 22 2d a4 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}