
rule Trojan_BAT_AgentTesla_PSZC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSZC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {20 e7 28 69 67 28 90 01 01 01 00 06 6f 61 00 00 0a 1c 0d 2b b4 07 75 11 00 00 02 20 fe 00 00 00 20 b1 02 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}