
rule Trojan_BAT_AgentTesla_PSZS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSZS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {17 8d 25 00 00 01 80 1a 00 00 04 7e 1a 00 00 04 16 fe 06 45 00 00 06 9b 2a } //00 00 
	condition:
		any of ($a_*)
 
}