
rule Trojan_BAT_AgentTesla_PTDE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {38 cd fd ff ff 28 90 01 01 00 00 0a 7e 01 00 00 04 02 08 6f 28 00 00 0a 28 90 01 01 00 00 0a a5 01 00 00 1b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}