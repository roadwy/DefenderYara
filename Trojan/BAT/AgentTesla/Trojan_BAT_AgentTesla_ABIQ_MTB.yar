
rule Trojan_BAT_AgentTesla_ABIQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABIQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {02 11 02 02 8e 69 5d 02 11 02 02 8e 69 5d 91 11 00 11 02 11 00 8e 69 5d 91 61 02 11 02 17 d6 02 8e 69 5d 91 da 20 90 01 03 00 d6 20 90 01 03 00 5d b4 9c 90 00 } //3
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_2 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_3 = {5f 00 5f 00 5f 00 5f 00 5f 00 5f 00 5f 00 5f 00 5f 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 _________.Resources
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}