
rule Trojan_BAT_AgentTesla_ASGG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASGG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 00 01 00 00 13 10 11 08 17 58 13 17 11 08 11 0e 5d 13 11 11 17 11 0e 5d 13 18 11 0d 11 18 91 11 10 58 13 19 11 0d 11 11 91 13 1a 11 1a 11 13 11 08 1f 16 5d 91 61 13 1b 11 1b 11 19 59 13 1c 11 0d 11 11 11 1c 11 10 5d d2 9c 11 08 17 58 13 08 11 08 11 0e 11 14 17 58 5a fe 04 13 1d 11 1d 2d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}