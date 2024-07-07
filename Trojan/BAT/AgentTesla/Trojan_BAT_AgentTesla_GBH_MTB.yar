
rule Trojan_BAT_AgentTesla_GBH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {7e e0 00 00 04 e0 16 9c 7e 2f 00 00 04 1f 15 8f 06 00 00 01 25 71 06 00 00 01 7e 06 00 00 04 16 9a 20 3a 01 00 00 95 61 81 06 00 00 01 08 2c 2a } //10
		$a_01_1 = {20 f1 0b 00 00 95 9e 7e bd 00 00 04 7e f8 00 00 04 18 9a 20 b3 03 00 00 20 01 01 01 01 13 04 95 61 80 bd 00 00 04 11 04 13 07 2b 76 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=10
 
}