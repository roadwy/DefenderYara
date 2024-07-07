
rule Trojan_BAT_LokiBot_XNFA_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.XNFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {20 00 01 00 00 6f 90 01 03 0a 09 08 6f 90 01 03 0a 09 18 6f 90 01 03 0a 09 6f 90 01 03 0a 06 16 06 8e 69 6f 90 01 03 0a 13 04 11 04 28 90 01 03 06 74 6b 00 00 01 6f 90 01 03 0a 17 9a 80 48 00 00 04 23 e2 e6 54 32 00 00 46 40 90 00 } //1
		$a_01_1 = {43 6f 6d 70 75 74 65 48 61 73 68 } //1 ComputeHash
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}