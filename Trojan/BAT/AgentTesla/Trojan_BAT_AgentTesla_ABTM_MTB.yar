
rule Trojan_BAT_AgentTesla_ABTM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 08 18 6f 90 01 01 00 00 0a 20 03 02 00 00 28 90 01 01 00 00 0a 13 04 07 11 04 6f 90 01 01 00 00 0a 08 18 58 0c 08 06 6f 90 01 01 00 00 0a fe 04 13 05 11 05 2d d1 90 00 } //6
	condition:
		((#a_03_0  & 1)*6) >=6
 
}