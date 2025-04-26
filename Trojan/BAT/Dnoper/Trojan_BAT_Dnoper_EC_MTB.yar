
rule Trojan_BAT_Dnoper_EC_MTB{
	meta:
		description = "Trojan:BAT/Dnoper.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {52 00 50 00 46 00 3a 00 53 00 6d 00 61 00 72 00 74 00 41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 } //1 RPF:SmartAssembly
		$a_01_1 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 2e 00 43 00 72 00 79 00 70 00 74 00 6f 00 67 00 72 00 61 00 70 00 68 00 79 00 2e 00 41 00 65 00 73 00 43 00 72 00 79 00 70 00 74 00 6f 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 50 00 72 00 6f 00 76 00 69 00 64 00 65 00 72 00 } //1 System.Security.Cryptography.AesCryptoServiceProvider
		$a_01_2 = {67 65 74 5f 41 6c 6c 6f 77 4f 6e 6c 79 46 69 70 73 41 6c 67 6f 72 69 74 68 6d 73 } //1 get_AllowOnlyFipsAlgorithms
		$a_01_3 = {57 6c 6c 4b 62 69 79 44 61 56 } //1 WllKbiyDaV
		$a_01_4 = {6f 42 4e 4b 31 45 4e 51 64 50 } //1 oBNK1ENQdP
		$a_01_5 = {63 4a 4d 4b 78 31 58 78 65 57 } //1 cJMKx1XxeW
		$a_01_6 = {41 65 73 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 AesCryptoServiceProvider
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}