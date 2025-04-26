
rule Trojan_BAT_AgentTesla_MBAQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b 16 13 04 2b 15 07 11 04 06 11 04 9a 1f 10 28 ?? 00 00 0a 9c 11 04 17 58 13 04 11 04 06 8e 69 fe 04 13 05 11 05 2d de } //1
		$a_01_1 = {20 00 53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 41 00 63 00 74 00 69 00 76 00 61 00 74 00 6f 00 72 00 20 00 } //1  System.Activator 
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}