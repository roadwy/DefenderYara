
rule Trojan_BAT_Remcos_NG_MTB{
	meta:
		description = "Trojan:BAT/Remcos.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 03 4b 04 4b 61 1f 7b 58 0a 03 4b 0b 03 04 4b 54 04 07 54 } //1
		$a_01_1 = {5f 0a 06 16 fe 01 0c 08 2c 04 00 17 0a 00 } //1
		$a_81_2 = {33 64 61 64 32 62 65 31 2d 64 39 63 32 2d 34 38 34 33 2d 62 31 38 39 2d 30 36 33 63 31 30 34 35 38 64 64 37 } //2 3dad2be1-d9c2-4843-b189-063c10458dd7
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*2) >=4
 
}
rule Trojan_BAT_Remcos_NG_MTB_2{
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