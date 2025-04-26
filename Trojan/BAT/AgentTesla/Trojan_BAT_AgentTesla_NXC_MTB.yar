
rule Trojan_BAT_AgentTesla_NXC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NXC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 9b 00 00 0a 0d 09 08 6f 9c 00 00 0a 09 18 6f 9d 00 00 0a 09 6f 9e 00 00 0a 06 16 06 8e 69 6f 9f 00 00 0a 13 04 11 04 } //1
		$a_01_1 = {97 a2 2b 09 0f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 99 00 00 00 30 00 00 00 b5 00 00 00 4b } //1
		$a_01_2 = {52 61 6e 64 6f 6d 4e 75 6d 62 65 72 47 61 6d 65 2e 50 72 6f 70 65 72 74 69 65 73 } //1 RandomNumberGame.Properties
		$a_01_3 = {33 32 32 38 64 31 65 35 32 66 30 62 } //1 3228d1e52f0b
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}