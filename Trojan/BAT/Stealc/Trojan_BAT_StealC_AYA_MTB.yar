
rule Trojan_BAT_StealC_AYA_MTB{
	meta:
		description = "Trojan:BAT/StealC.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_00_0 = {42 00 61 00 7a 00 61 00 69 00 64 00 42 00 4f 00 74 00 4e 00 65 00 74 00 } //2 BazaidBOtNet
		$a_01_1 = {24 63 62 32 61 61 65 36 65 2d 34 65 30 33 2d 34 31 66 37 2d 62 39 64 31 2d 31 62 38 39 65 38 62 31 63 66 32 32 } //1 $cb2aae6e-4e03-41f7-b9d1-1b89e8b1cf22
		$a_01_2 = {43 72 79 70 74 6f 4f 62 66 75 73 63 61 74 6f 72 5f 4f 75 74 70 75 74 } //1 CryptoObfuscator_Output
		$a_00_3 = {55 00 33 00 52 00 31 00 59 00 6c 00 4e 00 30 00 64 00 57 00 49 00 3d 00 } //1 U3R1YlN0dWI=
		$a_01_4 = {53 74 75 62 2e 52 65 73 6f 75 72 63 65 73 } //1 Stub.Resources
	condition:
		((#a_00_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}
rule Trojan_BAT_StealC_AYA_MTB_2{
	meta:
		description = "Trojan:BAT/StealC.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_01_0 = {24 65 65 39 37 64 36 35 32 2d 35 30 34 66 2d 34 64 61 36 2d 61 36 65 32 2d 32 36 62 64 37 37 33 62 63 33 63 33 } //2 $ee97d652-504f-4da6-a6e2-26bd773bc3c3
		$a_01_1 = {51 43 58 42 53 44 4a 48 49 55 57 45 36 34 33 2e 70 64 62 } //1 QCXBSDJHIUWE643.pdb
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_5 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=7
 
}