
rule Trojan_BAT_AgentTesla_ASFR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASFR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 11 09 11 0a 11 0b 28 ?? 00 00 06 13 0c 07 11 07 11 0c 20 00 01 00 00 5d d2 9c 00 11 06 17 59 13 06 } //1
		$a_01_1 = {11 06 07 8e 69 5d 13 07 11 06 08 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}