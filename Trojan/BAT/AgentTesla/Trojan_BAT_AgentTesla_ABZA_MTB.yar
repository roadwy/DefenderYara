
rule Trojan_BAT_AgentTesla_ABZA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 03 00 "
		
	strings :
		$a_03_0 = {07 09 11 04 28 90 01 01 00 00 06 13 06 08 12 06 28 90 01 01 00 00 0a 6f 90 00 } //01 00 
		$a_01_1 = {6d 00 65 00 6d 00 6f 00 72 00 79 00 5f 00 61 00 6c 00 6c 00 6f 00 63 00 61 00 74 00 6f 00 72 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}