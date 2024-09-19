
rule Trojan_BAT_Remcos_NG_MTB{
	meta:
		description = "Trojan:BAT/Remcos.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {11 20 61 11 18 19 58 61 11 32 61 d2 9c } //2
		$a_01_1 = {58 1d 11 20 58 61 d2 13 18 11 21 16 91 11 21 18 91 1e 62 60 11 18 19 62 58 } //2
		$a_01_2 = {13 22 11 0d 11 22 11 0f 59 61 13 0d 11 0f 11 0d 19 58 1e 63 59 } //2
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_4 = {44 79 6e 61 6d 69 63 49 6e 76 6f 6b 65 } //1 DynamicInvoke
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=8
 
}