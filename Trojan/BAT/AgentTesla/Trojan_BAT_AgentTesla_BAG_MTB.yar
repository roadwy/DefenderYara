
rule Trojan_BAT_AgentTesla_BAG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 9a 20 0f 09 00 00 95 2e 03 16 2b 01 17 17 59 11 42 16 9a 20 32 04 00 00 95 5f 11 42 16 9a 20 64 04 00 00 95 61 59 80 08 00 00 04 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}