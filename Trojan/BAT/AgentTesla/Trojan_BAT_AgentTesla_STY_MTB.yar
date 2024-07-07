
rule Trojan_BAT_AgentTesla_STY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.STY!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 13 0c 2b 47 00 07 11 0c 17 58 11 07 5d 91 13 0d 07 11 0c 91 13 0e 08 11 0c 08 6f 44 00 00 0a 5d 6f 45 00 00 0a 13 0f 11 0e 11 0f 61 11 0d 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 10 07 11 0c 11 10 d2 9c 00 11 0c 17 58 13 0c 11 0c 11 07 fe 04 13 11 11 11 2d ad } //1
		$a_01_1 = {16 0a 2b 3e 07 06 17 58 09 5d 91 13 0c 07 06 91 13 0d 08 06 08 6f 72 00 00 0a 5d 6f 73 00 00 0a 13 0e 11 0d 11 0e 61 11 0c 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 0f 07 06 11 0f d2 9c 06 17 58 0a 06 09 fe 04 13 10 11 10 2d b8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}