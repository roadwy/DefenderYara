
rule Trojan_BAT_AgentTesla_KABJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.KABJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 0d 11 04 11 0d 91 20 00 01 00 00 58 13 0e 11 04 11 0c 91 13 0f 11 0f 11 05 11 0b 1f 16 5d 91 61 13 10 11 04 11 0c 11 10 11 0e 59 20 00 01 00 00 5d d2 9c 00 11 0b 17 58 13 0b } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}