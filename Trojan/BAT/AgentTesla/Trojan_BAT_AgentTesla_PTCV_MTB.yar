
rule Trojan_BAT_AgentTesla_PTCV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTCV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {38 87 ff ff ff 12 01 7c 0b 00 00 04 12 01 28 90 01 01 00 00 2b 20 03 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}