
rule Trojan_BAT_AgentTesla_ASFH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASFH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 07 07 8e 69 6a 5d d4 07 11 07 07 8e 69 6a 5d d4 91 08 11 07 08 8e 69 6a 5d d4 91 61 28 ?? 00 00 0a 07 11 07 17 6a 58 07 8e 69 6a 5d d4 91 28 ?? 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? 00 00 0a 9c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_ASFH_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ASFH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0c 17 0d 2b 31 02 09 28 ?? 00 00 0a 03 09 03 6f ?? 00 00 0a 5d 17 d6 28 ?? 00 00 0a da 13 04 07 11 04 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 09 17 d6 0d 09 08 31 } //1
		$a_01_1 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 } //1 Invoke
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}