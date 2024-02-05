
rule Trojan_BAT_AgentTesla_DIB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 11 04 02 11 04 91 07 61 06 09 91 61 28 90 01 03 06 9c 90 00 } //01 00 
		$a_03_1 = {06 02 08 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 84 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}