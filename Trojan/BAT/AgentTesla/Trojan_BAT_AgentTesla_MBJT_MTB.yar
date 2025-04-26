
rule Trojan_BAT_AgentTesla_MBJT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 0a 07 11 05 91 13 0b 09 11 0a 6f ?? 01 00 0a 13 0c 02 07 06 28 ?? 00 00 06 13 0d 02 11 0b 11 0c 11 0d 28 ?? 00 00 06 13 0e 07 11 05 11 0e 20 00 01 00 00 5d d2 9c 06 17 59 0a 06 16 fe 04 16 fe 01 13 0f 11 0f 2d ae } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}