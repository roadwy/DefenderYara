
rule Trojan_BAT_AgentTesla_NHD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 28 90 01 03 0a 03 6f 90 01 03 0a 6f 90 01 03 0a 0a 7e 90 01 03 04 06 6f 90 01 03 0a 00 7e 90 01 03 04 18 6f 90 01 03 0a 00 7e 90 01 03 04 6f 90 01 03 0a 80 90 01 03 04 02 28 90 01 03 06 0c 7e 90 01 03 04 6f 90 01 03 0a 00 08 0d 2b 00 09 2a 90 00 } //01 00 
		$a_80_1 = {48 65 6c 70 65 72 5f 43 6c 61 73 73 65 73 } //Helper_Classes  01 00 
		$a_01_2 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //00 00  TransformFinalBlock
	condition:
		any of ($a_*)
 
}