
rule Trojan_BAT_AgentTesla_ABXC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABXC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {48 00 61 00 76 00 61 00 6e 00 6e 00 61 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //01 00 
		$a_01_1 = {61 39 62 34 34 30 65 62 2d 33 32 39 63 2d 34 32 31 36 2d 38 39 37 31 2d 36 34 35 38 66 31 63 32 39 30 31 39 } //00 00 
	condition:
		any of ($a_*)
 
}