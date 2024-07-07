
rule Trojan_BAT_AgentTesla_ASDY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASDY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {13 20 07 11 1b 11 20 20 00 01 00 00 5d d2 9c 00 11 1a 17 59 13 1a 11 1a 16 fe 04 16 fe 01 13 21 11 21 2d } //1
		$a_01_1 = {48 00 37 00 34 00 35 00 47 00 37 00 47 00 47 00 45 00 31 00 47 00 41 00 4a 00 34 00 35 00 37 00 37 00 38 00 42 00 37 00 43 00 39 00 } //1 H745G7GGE1GAJ45778B7C9
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}