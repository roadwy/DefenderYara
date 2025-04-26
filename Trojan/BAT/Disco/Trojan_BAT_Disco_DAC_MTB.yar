
rule Trojan_BAT_Disco_DAC_MTB{
	meta:
		description = "Trojan:BAT/Disco.DAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {11 04 18 6f ?? 00 00 0a 11 04 0c 28 ?? 00 00 0a 08 6f ?? 00 00 0a 07 16 07 8e 69 6f ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 0a de 22 7e ?? 00 00 04 18 9a 80 ?? 00 00 04 2b a1 } //3
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_3 = {61 36 32 66 34 34 64 37 37 31 34 31 34 32 36 65 39 66 61 32 31 36 66 33 32 64 30 63 64 30 63 31 } //1 a62f44d77141426e9fa216f32d0cd0c1
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1) >=6
 
}