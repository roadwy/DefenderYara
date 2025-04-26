
rule Trojan_BAT_AgentTesla_KABM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.KABM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 04 06 17 58 13 0b 06 08 5d 13 05 11 0b 08 5d 13 0c 07 11 0c 91 11 04 58 13 0d 07 11 05 91 13 0e 11 0e 11 07 06 1f 16 5d 91 61 13 0f 11 0f 11 0d 59 13 10 07 11 05 11 10 11 04 5d d2 9c 06 17 58 0a 06 08 11 08 17 58 5a fe 04 13 11 11 11 2d aa } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}