
rule Trojan_BAT_AgentTesla_KABH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.KABH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 15 91 13 17 07 11 15 11 17 08 11 14 1f 16 5d 91 61 07 11 16 11 04 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 00 11 14 17 58 13 14 11 14 11 04 09 17 58 5a fe 04 13 18 11 18 2d b2 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}