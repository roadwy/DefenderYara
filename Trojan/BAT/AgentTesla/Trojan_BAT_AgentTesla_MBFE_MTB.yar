
rule Trojan_BAT_AgentTesla_MBFE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBFE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 06 07 8e 69 0c 16 0a 2b 90 01 01 06 08 5d 0d 06 17 58 08 5d 90 00 } //1
		$a_01_1 = {91 61 07 11 09 91 59 20 00 01 00 00 58 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_MBFE_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MBFE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {34 00 4e 00 28 00 35 00 4b 00 28 00 39 00 7c 00 28 00 7c 00 7c 00 28 00 7c 00 33 00 28 00 7c 00 7c 00 28 00 7c 00 7c 00 28 00 7c 00 7c 00 28 00 7c 00 34 00 } //1 4N(5K(9|(||(|3(||(||(||(|4
		$a_01_1 = {20 00 4c 00 6f 00 2d 00 61 00 64 00 20 00 } //1  Lo-ad 
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}