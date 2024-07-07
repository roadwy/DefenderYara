
rule Trojan_BAT_AgentTesla_ETM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ETM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 04 17 58 7e 90 01 03 04 5d 91 0a 16 0b 03 04 28 90 01 03 06 0c 06 05 58 0d 08 09 59 05 5d 0b 03 04 7e 90 01 03 04 5d 07 d2 9c 03 13 04 11 04 2a 90 00 } //1
		$a_03_1 = {5d 91 0a 06 7e 90 01 03 04 03 1f 16 5d 6f 90 01 03 0a 61 0b 07 2a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}