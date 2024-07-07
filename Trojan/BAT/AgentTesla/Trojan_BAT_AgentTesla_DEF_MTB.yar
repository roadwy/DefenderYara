
rule Trojan_BAT_AgentTesla_DEF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DEF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_03_0 = {02 1f 2d 1f 2b 6f 90 01 03 0a 10 00 02 1f 5f 1f 2f 6f 90 01 03 0a 10 00 02 28 90 01 03 0a 0c 28 90 01 03 0a 06 6f 90 01 03 0a 0d 1f 10 90 00 } //10
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
		$a_01_3 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_4 = {00 74 65 78 74 54 6f 44 65 63 72 79 70 74 00 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}