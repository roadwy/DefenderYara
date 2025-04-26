
rule Trojan_BAT_AgentTesla_KABQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.KABQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 08 09 17 58 13 09 09 11 04 5d 13 0a 11 09 11 04 5d 13 0b 07 11 0b 91 11 08 58 13 0c 07 11 0a 91 13 0d 08 09 1f 16 5d 91 13 0e 11 0d 11 0e 61 13 0f 11 0f 11 0c 59 13 10 07 11 0a 11 10 11 08 5d d2 9c 09 17 58 0d } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}