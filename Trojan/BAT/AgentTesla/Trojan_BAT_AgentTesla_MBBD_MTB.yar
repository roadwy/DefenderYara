
rule Trojan_BAT_AgentTesla_MBBD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {34 00 44 00 2d 00 35 00 41 00 2d 00 39 00 7d 00 7e 00 2d 00 7d 00 33 00 7e 00 7e 00 7e 00 2d 00 7d 00 34 00 7e 00 7e 00 7e 00 2d 00 46 00 46 00 2d 00 46 00 46 00 7e 00 7e 00 2d 00 42 00 38 00 7e 00 7e } //00 00 
	condition:
		any of ($a_*)
 
}