
rule Trojan_BAT_AgentTesla_NJJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NJJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 45 04 00 00 95 5f 7e 60 00 00 04 1a 9a 20 fa 03 00 00 95 61 59 81 06 00 00 01 7e 60 00 00 04 11 08 13 0e 16 9a 1f 3e 95 7e 60 00 00 04 1a 9a 20 90 01 00 00 95 40 cc 00 00 00 7e 60 00 00 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}