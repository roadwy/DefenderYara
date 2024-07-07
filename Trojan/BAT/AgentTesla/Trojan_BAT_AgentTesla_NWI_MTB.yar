
rule Trojan_BAT_AgentTesla_NWI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NWI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 0c 00 00 04 20 02 0a 00 00 95 e0 95 7e 0c 00 00 04 20 b7 13 00 00 95 61 7e 0c 00 00 04 20 3d 03 00 00 95 2e 03 17 2b 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}