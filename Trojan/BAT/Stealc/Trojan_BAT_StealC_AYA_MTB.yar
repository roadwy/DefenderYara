
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