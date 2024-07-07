
rule Trojan_BAT_AgentTesla_PSAZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {53 79 6d 6d 65 74 72 69 63 41 6c 67 6f 72 69 74 68 6d } //1 SymmetricAlgorithm
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_2 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_3 = {49 43 72 79 70 74 6f 54 72 61 6e 73 66 6f 72 6d } //1 ICryptoTransform
		$a_01_4 = {41 6c 6c 6f 77 50 61 72 74 69 61 6c 6c 79 54 72 75 73 74 65 64 43 61 6c 6c 65 72 73 41 74 74 72 69 62 75 74 65 } //1 AllowPartiallyTrustedCallersAttribute
		$a_01_5 = {55 54 46 38 45 6e 63 6f 64 69 6e 67 } //1 UTF8Encoding
		$a_01_6 = {66 30 36 35 39 65 35 39 30 35 34 35 34 61 35 65 39 39 62 39 37 35 32 61 66 63 37 38 62 37 30 30 } //1 f0659e5905454a5e99b9752afc78b700
		$a_01_7 = {30 61 31 33 63 66 36 31 35 63 33 64 34 37 32 65 34 30 64 35 32 39 39 64 30 39 38 30 37 65 63 31 } //1 0a13cf615c3d472e40d5299d09807ec1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}