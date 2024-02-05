
rule Trojan_BAT_AgentTesla_EPT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EPT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {1f 10 0d 06 02 08 18 6f 90 01 03 0a 09 28 90 01 03 0a 84 28 90 01 03 0a 6f 90 01 03 0a 26 00 08 18 d6 0c 90 00 } //01 00 
		$a_01_1 = {02 11 04 91 07 61 06 09 91 61 13 05 08 11 04 11 05 d2 9c } //00 00 
	condition:
		any of ($a_*)
 
}