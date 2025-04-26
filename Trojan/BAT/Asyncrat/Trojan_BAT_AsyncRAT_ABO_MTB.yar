
rule Trojan_BAT_AsyncRAT_ABO_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.ABO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 42 00 00 0a 0a 06 28 43 00 00 0a 03 50 6f 44 00 00 0a 6f 45 00 00 0a 0b 73 46 00 00 0a 0c 08 07 6f 47 00 00 0a 08 28 62 00 00 06 6f 48 00 00 0a 08 6f 49 00 00 0a 02 50 28 63 00 00 06 02 50 8e 69 6f 4a 00 00 0a 2a } //4
		$a_01_1 = {53 79 6d 6d 65 74 72 69 63 41 6c 67 6f 72 69 74 68 6d } //1 SymmetricAlgorithm
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}