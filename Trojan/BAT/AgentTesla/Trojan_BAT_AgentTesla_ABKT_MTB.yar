
rule Trojan_BAT_AgentTesla_ABKT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABKT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {08 11 07 07 11 07 9a 1f 10 28 90 01 03 0a 6f 90 01 03 0a 00 11 07 90 00 } //02 00 
		$a_01_1 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 46 00 6f 00 72 00 6d 00 73 00 41 00 70 00 70 00 31 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 53 00 43 00 43 } //00 00 
	condition:
		any of ($a_*)
 
}