
rule Ransom_MSIL_HiddenTear_AHT_MTB{
	meta:
		description = "Ransom:MSIL/HiddenTear.AHT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_03_0 = {13 08 00 11 08 13 09 16 13 0a ?? ?? ?? ?? ?? 11 09 11 0a 9a 13 0b 00 11 0b 6f ?? 00 00 0a 2c 0f 11 0b 6f ?? 00 00 0a 19 fe 01 16 fe 01 2b 01 17 13 0e 11 0e 2c 05 } //2
		$a_01_1 = {54 68 65 20 53 65 63 75 72 69 74 79 20 6f 66 20 54 68 69 73 20 43 6f 6d 70 75 74 65 72 20 48 61 73 20 42 65 65 6e 20 43 6f 6d 70 72 6f 6d 69 73 65 64 } //1 The Security of This Computer Has Been Compromised
		$a_01_2 = {4a 75 70 69 74 65 72 4c 6f 63 6b 65 72 20 68 61 73 20 65 6e 63 72 79 70 74 65 64 20 61 6c 6c 20 74 68 65 20 64 61 74 61 20 6f 6e 20 74 68 69 73 20 63 6f 6d 70 75 74 65 72 20 77 69 74 68 20 6d 69 6c 69 74 61 72 79 2d 67 72 61 64 65 20 41 45 53 2d 32 35 36 20 65 6e 63 72 79 70 74 69 6f 6e } //3 JupiterLocker has encrypted all the data on this computer with military-grade AES-256 encryption
		$a_01_3 = {57 65 20 74 61 6b 65 20 6f 75 72 20 77 6f 72 6b 20 73 65 72 69 6f 75 73 6c 79 20 61 6e 64 20 75 6e 64 65 72 73 74 61 6e 64 20 74 68 61 74 20 79 6f 75 72 20 64 61 74 61 20 6d 61 79 20 62 65 20 73 65 6e 73 69 74 69 76 65 20 6f 72 20 69 6d 70 6f 72 74 61 6e 74 } //1 We take our work seriously and understand that your data may be sensitive or important
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3+(#a_01_3  & 1)*1) >=7
 
}