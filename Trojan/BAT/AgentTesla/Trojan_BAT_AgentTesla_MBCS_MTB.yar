
rule Trojan_BAT_AgentTesla_MBCS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBCS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0c 2b 19 00 03 07 08 6f 90 01 01 00 00 0a 0d 06 07 12 03 28 90 01 01 00 00 0a 9c 00 08 17 58 0c 08 03 6f 90 01 01 00 00 0a fe 04 13 04 11 04 2d d8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}