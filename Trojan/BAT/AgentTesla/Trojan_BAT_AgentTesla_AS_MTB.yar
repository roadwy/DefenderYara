
rule Trojan_BAT_AgentTesla_AS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 08 6f 17 00 00 0a 0d 00 09 28 18 00 00 0a 72 53 00 00 70 28 19 00 00 0a 1f 1e 5d 5b 28 1a 00 00 0a 13 05 12 05 28 1b 00 00 0a 13 04 06 11 04 6f 1c 00 00 0a 26 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_AS_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {19 9a 20 b9 04 00 00 95 5f 7e 2e 00 00 04 19 9a 20 20 05 00 00 95 61 59 81 08 00 00 01 38 12 02 00 00 7e 09 00 00 04 1f 32 95 } //2
		$a_01_1 = {16 2b 01 17 17 59 7e 21 00 00 04 20 41 05 00 00 95 5f 7e 21 00 00 04 20 ae 06 00 00 95 61 61 09 0d 81 08 00 00 01 7e 09 00 00 04 1f 12 95 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}