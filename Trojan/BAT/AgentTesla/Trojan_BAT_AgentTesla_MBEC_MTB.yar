
rule Trojan_BAT_AgentTesla_MBEC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 05 11 04 6f 90 01 01 01 00 0a 13 06 11 05 11 06 d0 90 01 01 00 00 02 28 90 01 01 00 00 0a 6f 90 01 01 01 00 0a 74 90 01 01 00 00 02 0d de 0c 90 00 } //1
		$a_01_1 = {62 34 62 64 32 39 61 38 33 61 39 39 } //1 b4bd29a83a99
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}