
rule Trojan_BAT_AgentTesla_ENR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ENR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 06 20 00 14 01 00 5d 07 06 20 00 14 01 00 5d 91 08 06 1f 16 5d 6f 90 01 03 0a 61 07 06 17 58 20 00 14 01 00 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_ENR_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ENR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 09 20 00 0a 01 00 5d 07 09 20 00 0a 01 00 5d 91 08 09 1f 16 5d 6f 90 01 03 0a 61 07 09 17 58 20 00 0a 01 00 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_ENR_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.ENR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 11 07 07 11 07 91 7e 90 01 03 04 11 07 7e 90 01 03 04 6f 90 01 03 0a 5d 6f 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 61 9c 11 07 17 d6 13 07 90 00 } //01 00 
		$a_01_1 = {00 43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 00 } //00 00  䌀敲瑡䥥獮慴据e
	condition:
		any of ($a_*)
 
}