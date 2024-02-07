
rule Trojan_BAT_AgentTesla_NZR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NZR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {20 00 ea 00 00 fe 04 13 08 11 08 2d } //01 00 
		$a_01_1 = {53 70 6c 69 74 } //01 00  Split
		$a_01_2 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_01_3 = {52 65 70 6c 61 63 65 } //00 00  Replace
	condition:
		any of ($a_*)
 
}