
rule Trojan_BAT_AgentTesla_KAAF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.KAAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 08 11 05 07 11 05 18 5a 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a d2 9c 00 11 05 17 58 13 05 11 05 08 8e 69 fe 04 13 06 11 06 2d d4 90 00 } //10
		$a_01_1 = {34 00 43 00 30 00 31 00 30 00 33 00 5a 00 5a 00 34 00 41 00 45 00 41 00 42 00 37 00 36 00 } //10 4C0103ZZ4AEAB76
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}