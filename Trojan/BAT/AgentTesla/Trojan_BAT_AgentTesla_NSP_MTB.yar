
rule Trojan_BAT_AgentTesla_NSP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NSP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {02 6f 93 00 00 0a 08 07 5d 91 0d 0e 04 08 0e 05 58 03 08 04 58 91 02 6f 91 00 00 0a 09 06 5d 91 61 d2 9c 08 17 58 0c 08 05 32 d5 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_2 = {47 65 6e 65 72 61 74 65 4b 65 79 } //01 00  GenerateKey
		$a_01_3 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  TransformFinalBlock
		$a_80_4 = {52 69 6a 6e 64 61 65 6c } //Rijndael  00 00 
	condition:
		any of ($a_*)
 
}