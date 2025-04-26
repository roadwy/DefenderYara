
rule Trojan_BAT_AgentTesla_MBEX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBEX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 0e 11 05 11 0c 91 61 11 04 11 0d 91 59 11 0f 58 11 0f 5d 13 10 11 04 11 0b 11 10 d2 9c 11 08 17 58 13 08 00 11 08 11 07 11 06 17 58 5a fe 04 13 11 11 11 2d a4 } //1
		$a_01_1 = {37 00 38 00 42 00 53 00 37 00 47 00 46 00 38 00 35 00 41 00 54 00 38 00 50 00 51 00 47 00 34 00 46 00 39 00 38 00 37 00 34 00 59 00 } //1 78BS7GF85AT8PQG4F9874Y
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}