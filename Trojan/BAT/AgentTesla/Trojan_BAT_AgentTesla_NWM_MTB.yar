
rule Trojan_BAT_AgentTesla_NWM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NWM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {20 36 09 00 00 95 e0 95 7e 31 00 00 04 1a 9a 20 e4 04 00 00 95 61 7e 31 00 00 04 1a 9a 20 7c 0b 00 00 95 2e 03 17 } //1
		$a_01_1 = {20 d9 09 00 00 95 e0 95 7e 2f 00 00 04 1b 9a 20 e4 07 00 00 95 61 7e 2f 00 00 04 1b 9a 20 f6 0c 00 00 95 2e 03 17 2b 01 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}