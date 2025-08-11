
rule Trojan_Win32_Amadey_NMQ_MTB{
	meta:
		description = "Trojan:Win32/Amadey.NMQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_01_0 = {41 70 70 50 6f 6c 69 63 79 47 65 74 50 72 6f 63 65 73 73 54 65 72 6d 69 6e 61 74 69 6f 6e 4d 65 74 68 6f 64 } //1 AppPolicyGetProcessTerminationMethod
		$a_01_1 = {55 53 4e 70 56 78 39 6c 62 78 71 20 54 5a 74 6c 20 74 5a 67 36 44 6f 59 } //1 USNpVx9lbxq TZtl tZg6DoY
		$a_01_2 = {51 77 4e 7a 56 59 4e 69 62 4c 4b 6a 39 44 42 39 } //1 QwNzVYNibLKj9DB9
		$a_01_3 = {49 6f 32 41 52 42 63 31 59 4e 71 56 55 54 4a 58 20 64 66 57 39 4e 3d 3d } //1 Io2ARBc1YNqVUTJX dfW9N==
		$a_01_4 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //1 InternetOpenUrlA
		$a_01_5 = {37 39 31 39 37 37 30 36 38 30 65 39 62 62 30 34 38 32 39 63 30 30 65 35 62 63 30 34 37 63 33 62 } //1 7919770680e9bb04829c00e5bc047c3b
		$a_01_6 = {65 30 64 32 37 66 30 34 33 33 31 37 38 64 31 35 37 61 38 61 31 38 34 38 61 37 35 62 63 61 32 63 } //2 e0d27f0433178d157a8a1848a75bca2c
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*2) >=8
 
}