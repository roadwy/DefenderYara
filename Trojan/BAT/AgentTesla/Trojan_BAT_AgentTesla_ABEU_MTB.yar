
rule Trojan_BAT_AgentTesla_ABEU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABEU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 04 00 "
		
	strings :
		$a_03_0 = {0a 06 18 6f 90 01 03 0a 06 6f 90 01 03 0a 13 04 02 0d 11 04 09 16 09 8e b7 6f 90 01 03 0a 0b de 11 de 0f 90 0a 3d 00 06 08 28 90 01 03 0a 7e 90 01 03 04 6f 90 01 03 0a 6f 90 01 03 0a 6f 90 00 } //01 00 
		$a_01_1 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  TransformFinalBlock
		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}