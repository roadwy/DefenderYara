
rule Trojan_BAT_AgentTesla_NVU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NVU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 29 00 00 04 17 9a 7e 29 00 00 04 16 9a 20 a3 0b 00 00 95 e0 95 7e 29 00 00 04 16 9a 20 23 07 00 00 95 61 7e 29 00 00 04 16 9a 20 ea 01 00 00 95 2e 03 17 2b 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}