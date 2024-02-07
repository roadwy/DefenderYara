
rule Trojan_BAT_AgentTesla_NTJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NTJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 11 05 17 da 6f 90 01 03 0a 08 11 05 08 6f 90 01 03 0a 5d 6f 90 01 03 0a da 13 06 09 11 06 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 0d 11 05 17 d6 13 05 11 05 11 04 31 c5 90 00 } //01 00 
		$a_01_1 = {49 00 33 06 6e 00 76 00 33 06 6f 00 6b 00 33 06 65 00 } //01 00  Iسnvسokسe
		$a_01_2 = {42 00 75 00 6e 00 00 0b 69 00 66 00 75 00 5f 00 54 00 00 07 65 00 78 00 74 00 00 07 42 00 6f 00 78 } //00 00 
	condition:
		any of ($a_*)
 
}