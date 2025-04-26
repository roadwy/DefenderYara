
rule Trojan_BAT_AgentTesla_ASGF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASGF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {11 0e 08 11 08 1f 16 5d 91 61 13 0f 11 } //1
		$a_01_1 = {11 0f 11 0d 59 13 10 07 11 0b 11 10 11 09 5d d2 9c } //1
		$a_01_2 = {20 00 01 00 00 13 09 11 08 17 58 13 0a 11 08 11 04 5d 13 0b } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}