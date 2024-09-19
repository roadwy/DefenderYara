
rule Trojan_BAT_Formbook_NZB_MTB{
	meta:
		description = "Trojan:BAT/Formbook.NZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 06 18 d8 0a 06 07 fe 02 13 05 11 05 2c 02 07 0a 00 06 07 5d 16 } //3
		$a_81_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_81_2 = {57 65 62 53 65 72 76 69 63 65 73 } //1 WebServices
	condition:
		((#a_01_0  & 1)*3+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=5
 
}
rule Trojan_BAT_Formbook_NZB_MTB_2{
	meta:
		description = "Trojan:BAT/Formbook.NZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {25 16 1f 25 9d 6f ?? 00 00 0a 13 04 38 ?? ?? ?? ?? 00 02 } //3
		$a_81_1 = {4d 61 6e 61 67 65 6d 65 6e 74 5f 53 79 73 74 65 6d 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 } //1 Management_System.Properties.Resource
		$a_81_2 = {33 39 39 30 35 66 63 37 35 62 33 33 } //1 39905fc75b33
	condition:
		((#a_03_0  & 1)*3+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=5
 
}
rule Trojan_BAT_Formbook_NZB_MTB_3{
	meta:
		description = "Trojan:BAT/Formbook.NZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {04 8e 69 5d 93 03 61 d2 2a } //1
		$a_01_1 = {42 00 4c 00 59 00 41 00 54 00 20 00 4c 00 42 00 4c 00 59 00 41 00 54 00 20 00 6f 00 61 00 42 00 4c 00 59 00 41 00 54 00 20 00 64 00 42 00 4c 00 59 00 41 00 54 00 } //1 BLYAT LBLYAT oaBLYAT dBLYAT
		$a_01_2 = {42 00 4c 00 59 00 41 00 54 00 20 00 47 00 42 00 4c 00 59 00 41 00 54 00 20 00 65 00 42 00 4c 00 59 00 41 00 54 00 20 00 74 00 42 00 4c 00 59 00 41 00 54 00 20 00 54 00 42 00 4c 00 59 00 41 00 54 00 20 00 79 00 42 00 4c 00 59 00 41 00 54 00 20 00 70 00 42 00 4c 00 59 00 41 00 54 00 20 00 65 00 } //1 BLYAT GBLYAT eBLYAT tBLYAT TBLYAT yBLYAT pBLYAT e
		$a_01_3 = {42 00 4c 00 59 00 41 00 54 00 20 00 45 00 6e 00 42 00 4c 00 59 00 41 00 54 00 20 00 74 00 72 00 42 00 4c 00 59 00 41 00 54 00 20 00 79 00 50 00 42 00 4c 00 59 00 41 00 54 00 20 00 6f 00 69 00 42 00 4c 00 59 00 41 00 54 00 20 00 6e 00 74 00 42 00 4c 00 59 00 41 00 54 00 } //1 BLYAT EnBLYAT trBLYAT yPBLYAT oiBLYAT ntBLYAT
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}