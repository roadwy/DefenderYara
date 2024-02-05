
rule Trojan_BAT_AgentTesla_JNM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JNM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {09 11 04 9a 13 05 11 05 28 90 01 03 0a 90 01 09 59 28 90 01 03 0a b7 13 06 07 11 06 28 90 01 03 0a 6f 90 01 03 0a 26 00 11 04 17 d6 13 04 11 04 09 8e 69 fe 04 13 07 11 07 2d bf 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}