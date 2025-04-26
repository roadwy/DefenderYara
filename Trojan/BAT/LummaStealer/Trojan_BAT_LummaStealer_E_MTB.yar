
rule Trojan_BAT_LummaStealer_E_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {08 16 07 16 1f 10 } //2 ᘈᘇဟ
		$a_01_1 = {08 16 07 1f 0f 1f 10 } //2
		$a_01_2 = {09 04 16 04 8e 69 6f } //2
		$a_01_3 = {52 65 73 6f 75 72 63 65 4d 61 6e 61 67 65 72 } //1 ResourceManager
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}
rule Trojan_BAT_LummaStealer_E_MTB_2{
	meta:
		description = "Trojan:BAT/LummaStealer.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {6f 45 4c 57 58 53 59 71 55 6a 66 76 4a 4f 4d 75 71 67 45 4f 43 4a 46 63 42 63 6b 65 46 } //1 oELWXSYqUjfvJOMuqgEOCJFcBckeF
		$a_01_1 = {64 4b 41 6f 4d 7a 56 64 6f 47 4d 52 41 75 55 70 6e 7a 48 4c 59 49 78 2e 64 6c 6c } //1 dKAoMzVdoGMRAuUpnzHLYIx.dll
		$a_01_2 = {49 45 48 46 65 6c 62 57 70 66 73 6b 52 4b 4f 62 74 4e 45 4f 79 50 73 4b 64 46 50 68 4b } //1 IEHFelbWpfskRKObtNEOyPsKdFPhK
		$a_01_3 = {62 46 49 53 51 46 58 5a 72 6c 68 6f 77 53 70 70 6a 4d 63 55 4d 45 57 4d 56 4f 2e 64 6c 6c } //2 bFISQFXZrlhowSppjMcUMEWMVO.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=5
 
}