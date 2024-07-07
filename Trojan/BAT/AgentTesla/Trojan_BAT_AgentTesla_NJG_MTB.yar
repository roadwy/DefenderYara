
rule Trojan_BAT_AgentTesla_NJG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NJG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {20 e8 06 00 00 95 5f 7e 07 00 00 04 18 9a 20 78 02 00 00 95 61 59 81 05 00 00 01 38 5a 03 00 00 7e 04 00 00 04 1f 4c 95 7e 07 00 00 04 18 9a 20 87 03 00 00 } //1
		$a_01_1 = {20 f6 04 00 00 95 33 27 7e 38 00 00 04 18 9a 1f 34 8f 06 00 00 01 25 71 06 00 00 01 7e 38 00 00 04 17 9a 20 cd 04 00 00 95 61 81 06 00 00 01 7e 38 00 00 04 18 9a 1f 34 95 7e 38 00 00 04 17 9a 20 95 03 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}