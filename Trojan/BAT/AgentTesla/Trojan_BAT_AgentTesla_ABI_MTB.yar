
rule Trojan_BAT_AgentTesla_ABI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {1a 9a 20 13 04 00 00 95 2e 03 16 2b 01 17 17 59 7e 3b 00 00 04 1a 9a 20 04 04 00 00 95 5f 7e 3b 00 00 04 1a 9a 20 3c 03 00 00 95 20 01 01 01 01 13 0e 61 58 81 0a 00 00 01 } //2
		$a_01_1 = {1f 40 95 7e 2e 00 00 04 37 03 16 2b 01 17 17 11 04 13 04 59 7e 16 00 00 04 16 9a 20 ab 12 00 00 95 5f 7e 16 00 00 04 16 9a 20 f3 12 00 00 95 61 58 81 05 00 00 01 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}