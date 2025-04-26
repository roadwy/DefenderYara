
rule Trojan_BAT_AgentTesla_DAK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {1f 1d 95 34 03 16 2b 01 17 17 59 7e 21 00 00 04 20 2e 04 00 00 95 5f 7e 21 00 00 04 20 9c 02 00 00 95 61 58 80 10 00 00 04 } //2
		$a_01_1 = {11 2a 16 95 7e 1f 00 00 04 6f 05 00 00 0a 37 03 16 2b 01 17 17 59 7e 21 00 00 04 20 12 03 00 00 95 5f 7e 21 00 00 04 20 a2 01 00 00 95 61 58 80 10 00 00 04 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}