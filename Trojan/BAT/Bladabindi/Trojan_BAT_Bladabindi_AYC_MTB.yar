
rule Trojan_BAT_Bladabindi_AYC_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.AYC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {63 72 79 70 74 65 72 30 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //2 crypter0.My.Resources
		$a_01_1 = {24 35 61 32 31 34 33 62 39 2d 62 38 36 36 2d 34 33 33 34 2d 62 62 36 39 2d 66 64 35 38 36 34 33 65 34 37 37 31 } //2 $5a2143b9-b866-4334-bb69-fd58643e4771
		$a_01_2 = {45 78 74 72 61 63 74 41 6e 64 52 75 6e 45 78 65 } //1 ExtractAndRunExe
		$a_01_3 = {44 65 63 72 79 70 74 46 69 6c 65 } //1 DecryptFile
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_5 = {57 72 69 74 65 41 6c 6c 42 79 74 65 73 } //1 WriteAllBytes
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}