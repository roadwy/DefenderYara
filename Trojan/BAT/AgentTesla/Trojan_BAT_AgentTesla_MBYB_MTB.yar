
rule Trojan_BAT_AgentTesla_MBYB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBYB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {34 00 44 00 35 00 41 00 39 00 7c 00 7c 00 33 00 7c 00 7c 00 7c 00 30 00 34 00 7c 00 7c 00 7c 00 46 00 46 00 46 00 46 00 7c 00 7c 00 42 00 38 00 7c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}