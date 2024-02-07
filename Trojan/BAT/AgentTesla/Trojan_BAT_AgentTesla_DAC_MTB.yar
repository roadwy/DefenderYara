
rule Trojan_BAT_AgentTesla_DAC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 02 08 93 06 08 06 6f 90 01 03 0a 5d 6f 90 01 03 0a 61 d1 6f 90 01 03 0a 26 08 17 58 0c 08 02 8e 69 90 00 } //01 00 
		$a_01_1 = {54 6f 43 68 61 72 41 72 72 61 79 } //01 00  ToCharArray
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 } //00 00  FromBase64
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_DAC_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.DAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 03 00 "
		
	strings :
		$a_03_0 = {0d 16 13 07 2b 17 00 09 11 07 08 11 07 9a 1f 10 28 90 01 01 00 00 0a 9c 00 11 07 17 58 13 07 11 07 08 8e 69 fe 04 13 08 11 08 2d dc 90 00 } //01 00 
		$a_01_1 = {53 70 6c 69 74 } //01 00  Split
		$a_01_2 = {54 6f 42 79 74 65 } //00 00  ToByte
	condition:
		any of ($a_*)
 
}