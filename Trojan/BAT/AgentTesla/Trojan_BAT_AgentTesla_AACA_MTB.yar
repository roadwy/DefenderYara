
rule Trojan_BAT_AgentTesla_AACA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AACA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {66 65 33 62 61 36 63 62 2d 30 39 61 65 2d 34 64 63 65 2d 61 37 64 37 2d 37 35 39 33 63 61 65 33 66 32 65 37 } //00 00  fe3ba6cb-09ae-4dce-a7d7-7593cae3f2e7
	condition:
		any of ($a_*)
 
}