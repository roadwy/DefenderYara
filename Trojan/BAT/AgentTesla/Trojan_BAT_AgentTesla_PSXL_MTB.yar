
rule Trojan_BAT_AgentTesla_PSXL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSXL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {7e f0 01 00 04 6f 90 01 01 03 00 0a 74 d0 00 00 01 fe 09 00 00 8c 42 00 00 01 6f 90 01 01 03 00 0a 74 19 00 00 01 2a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}