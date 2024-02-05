
rule Trojan_BAT_AgentTesla_MBEI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBEI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 37 66 65 39 30 31 63 66 2d 33 31 34 64 2d 34 32 63 36 2d 61 37 38 66 2d 38 36 61 32 37 64 64 35 35 36 65 63 } //01 00 
		$a_01_1 = {47 65 74 50 69 78 65 6c } //00 00 
	condition:
		any of ($a_*)
 
}