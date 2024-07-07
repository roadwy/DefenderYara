
rule Trojan_BAT_AgentTesla_NUY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NUY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {04 5d 91 0a 06 7e 90 01 03 04 03 1f 16 5d 6f 90 01 03 0a 61 0b 2b 00 07 90 00 } //1
		$a_03_1 = {02 03 17 58 7e 90 01 03 04 5d 91 0a 16 0b 17 0c 00 02 03 28 90 01 03 06 0d 06 04 58 13 04 09 11 04 59 04 5d 0b 00 02 03 7e 90 01 03 04 5d 07 d2 9c 02 13 05 2b 00 90 00 } //1
		$a_01_2 = {57 1f a2 09 09 03 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 6b 00 00 00 13 00 00 00 70 00 00 00 9e } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}