
rule Trojan_BAT_AgentTesla_CSTE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CSTE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 21 00 07 09 11 04 6f 90 01 04 13 06 08 12 06 28 90 01 04 6f 90 01 04 00 11 04 17 58 13 04 00 11 04 07 6f 90 01 04 fe 04 13 07 11 07 2d cf 09 17 58 0d 00 09 07 6f 90 01 04 fe 04 13 08 11 08 2d b5 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}