
rule Ransom_Win32_Lambda_MB_MTB{
	meta:
		description = "Ransom:Win32/Lambda.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {4c 00 41 00 4d 00 42 00 44 00 41 00 5f 00 52 00 45 00 41 00 44 00 4d 00 45 00 2e 00 74 00 78 00 74 00 } //1 LAMBDA_README.txt
		$a_01_1 = {52 00 45 00 43 00 59 00 43 00 4c 00 45 00 52 00 } //1 RECYCLER
		$a_01_2 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 53 00 68 00 61 00 64 00 6f 00 77 00 43 00 6f 00 70 00 79 00 } //1 SELECT * FROM Win32_ShadowCopy
		$a_01_3 = {52 00 4f 00 4f 00 54 00 5c 00 43 00 49 00 4d 00 56 00 32 00 } //1 ROOT\CIMV2
		$a_01_4 = {5c 00 4c 00 61 00 6d 00 62 00 64 00 61 00 44 00 65 00 62 00 75 00 67 00 2e 00 74 00 78 00 74 00 } //1 \LambdaDebug.txt
		$a_01_5 = {47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 4c 00 61 00 6d 00 62 00 64 00 61 00 4d 00 75 00 74 00 65 00 78 00 } //1 Global\LambdaMutex
		$a_01_6 = {4c 61 6d 62 64 61 20 52 61 6e 73 6f 6d 77 61 72 65 } //1 Lambda Ransomware
		$a_01_7 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 20 61 6e 64 20 73 74 6f 6c 65 6e 2c 20 62 75 74 20 79 6f 75 20 6e 65 65 64 20 74 6f 20 66 6f 6c 6c 6f 77 20 6f 75 72 20 69 6e 73 74 72 75 63 74 69 6f 6e 73 2e 20 6f 74 68 65 72 77 69 73 65 2c 20 79 6f 75 20 63 61 6e 74 20 72 65 74 75 72 6e 20 79 6f 75 72 20 64 61 74 61 } //1 All your files are encrypted and stolen, but you need to follow our instructions. otherwise, you cant return your data
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}