
rule Trojan_BAT_Bladabindi_ABRM_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.ABRM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_2 = {50 4e 74 49 31 66 4c 74 34 55 6f 36 73 48 62 6a 4f 5a 2e 68 34 63 58 51 6f 70 72 48 48 73 58 4a 37 6e 34 46 54 } //3 PNtI1fLt4Uo6sHbjOZ.h4cXQoprHHsXJ7n4FT
		$a_01_3 = {69 57 39 77 38 44 73 48 41 6f 6d 72 6a 59 70 52 77 69 2e 69 69 68 42 6a 6f 68 36 32 59 69 47 58 73 4d 67 42 52 } //3 iW9w8DsHAomrjYpRwi.iihBjoh62YiGXsMgBR
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3) >=8
 
}