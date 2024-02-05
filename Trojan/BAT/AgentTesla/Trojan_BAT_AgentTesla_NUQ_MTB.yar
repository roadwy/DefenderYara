
rule Trojan_BAT_AgentTesla_NUQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NUQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {04 03 1f 16 5d 28 90 01 04 61 0b 08 20 90 00 } //01 00 
		$a_03_1 = {06 03 04 17 58 20 00 78 00 00 5d 91 28 90 01 01 00 00 06 59 05 58 05 5d 0a 90 00 } //01 00 
		$a_01_2 = {61 30 33 34 31 37 30 33 64 63 66 65 } //00 00 
	condition:
		any of ($a_*)
 
}