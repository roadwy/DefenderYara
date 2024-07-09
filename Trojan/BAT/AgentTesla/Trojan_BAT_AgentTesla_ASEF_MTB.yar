
rule Trojan_BAT_AgentTesla_ASEF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASEF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 0b 02 11 09 11 0a 11 0b 28 ?? 00 00 06 13 0c 07 11 07 11 0c 20 00 01 00 00 5d d2 9c 00 11 06 17 59 13 06 11 06 16 fe 04 16 fe 01 13 0d 11 0d 2d } //1
		$a_01_1 = {48 00 54 00 35 00 37 00 54 00 51 00 38 00 48 00 37 00 5a 00 52 00 39 00 50 00 35 00 30 00 38 00 37 00 56 00 5a 00 48 00 38 00 32 00 } //1 HT57TQ8H7ZR9P5087VZH82
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}