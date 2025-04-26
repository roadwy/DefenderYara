
rule Trojan_BAT_AgentTesla_AJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {19 9a 20 af 11 00 00 95 e0 95 7e 23 00 00 04 19 9a 20 98 10 00 00 95 61 7e 23 00 00 04 19 9a 20 0f 0a 00 00 95 2e 03 17 2b 01 16 58 6a } //2
		$a_01_1 = {17 9a 1f 3d 95 2c 03 16 2b 01 17 17 59 7e 23 00 00 04 19 9a 20 59 13 00 00 95 5f 7e 23 00 00 04 19 9a 20 2a 12 00 00 95 61 59 81 05 00 00 01 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}