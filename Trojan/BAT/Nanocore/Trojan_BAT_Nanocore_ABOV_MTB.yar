
rule Trojan_BAT_Nanocore_ABOV_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABOV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 0d 1c 2c a1 09 02 16 02 8e 69 6f 90 01 03 0a 2a 0a 38 90 01 03 ff 0b 38 90 01 03 ff 0c 2b aa 28 90 01 03 0a 2b b4 28 90 01 03 0a 2b bc 90 0a 33 00 06 6f 90 00 } //3
		$a_01_1 = {53 79 6d 6d 65 74 72 69 63 41 6c 67 6f 72 69 74 68 6d } //1 SymmetricAlgorithm
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}