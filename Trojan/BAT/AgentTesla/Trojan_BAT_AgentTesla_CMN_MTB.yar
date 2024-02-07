
rule Trojan_BAT_AgentTesla_CMN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CMN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 28 90 01 03 0a 72 90 01 03 70 6f 90 01 03 0a 6f 90 01 03 0a 0c 06 08 6f 90 01 03 0a 06 18 6f 90 01 03 0a 02 0d 06 6f 90 01 03 0a 09 16 09 8e 69 6f 90 01 03 0a 13 04 de 1f 07 2c 06 07 6f 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_2 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  TransformFinalBlock
		$a_01_3 = {00 43 6c 61 73 73 4c 69 62 72 61 72 79 00 } //00 00  䌀慬獳楌牢牡y
	condition:
		any of ($a_*)
 
}