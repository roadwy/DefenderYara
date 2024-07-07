
rule Trojan_BAT_AgentTesla_AZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 9a 20 72 0d 00 00 95 e0 7e 1a 00 00 04 16 9a 20 88 0e 00 00 95 d2 9c 7e 2a 00 00 04 7e 1a 00 00 04 16 9a 20 c5 06 00 00 95 61 } //2
		$a_01_1 = {16 9a 20 b1 07 00 00 95 e0 95 7e 1a 00 00 04 16 9a 20 38 10 00 00 95 61 7e 1a 00 00 04 16 9a 20 69 11 00 00 95 2e 03 17 2b 01 16 58 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}