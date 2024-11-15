
rule Trojan_BAT_AgentTesla_SMJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SMJ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 11 05 91 11 04 11 05 91 3b 02 00 00 00 16 2a 11 05 17 58 13 05 11 05 09 8e 69 32 e3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_SMJ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.SMJ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 0a 38 fc 00 00 00 16 0b 38 e5 00 00 00 06 18 5d 2c 0a 02 06 07 6f 3b 00 00 0a 2b 08 02 06 07 6f 3b 00 00 0a 0c 04 03 6f 3c 00 00 0a 59 0d 12 02 28 3d 00 00 0a 13 04 12 02 28 3e 00 00 0a 13 05 12 02 28 3f 00 00 0a 13 06 19 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}