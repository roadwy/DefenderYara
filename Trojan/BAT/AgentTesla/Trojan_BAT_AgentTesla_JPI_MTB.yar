
rule Trojan_BAT_AgentTesla_JPI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JPI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 28 90 01 03 0a 03 6f 90 01 03 0a 6f 90 01 03 0a 0a 7e 90 01 03 04 06 6f 90 01 03 0a 00 7e 90 01 03 04 18 6f 90 01 03 0a 00 7e 90 01 03 04 6f 90 01 03 0a 0c 08 02 16 02 8e 69 6f 90 00 } //01 00 
		$a_81_1 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //00 00  TransformFinalBlock
	condition:
		any of ($a_*)
 
}