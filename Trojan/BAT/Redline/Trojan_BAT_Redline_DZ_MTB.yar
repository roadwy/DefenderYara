
rule Trojan_BAT_Redline_DZ_MTB{
	meta:
		description = "Trojan:BAT/Redline.DZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {53 4a 79 57 73 4f 65 49 79 65 43 52 6b 4c 62 6e 50 58 6e 78 74 71 6f 6f 73 6b 4a 63 } //1 SJyWsOeIyeCRkLbnPXnxtqooskJc
		$a_81_1 = {62 62 67 6f 47 66 43 53 41 72 57 48 45 73 41 75 77 46 48 41 54 73 5a 58 2e 64 6c 6c } //1 bbgoGfCSArWHEsAuwFHATsZX.dll
		$a_81_2 = {59 56 62 74 67 70 6a 74 4e 62 52 63 6c 46 68 54 49 59 72 58 42 73 6e 56 4e } //1 YVbtgpjtNbRclFhTIYrXBsnVN
		$a_81_3 = {42 56 4d 41 6a 49 4a 45 4c 65 79 56 4b 6a 63 6d 42 67 4a 51 44 4c 49 4f 4e 56 46 70 } //1 BVMAjIJELeyVKjcmBgJQDLIONVFp
		$a_81_4 = {69 78 49 4b 6a 62 4a 6a 61 52 41 64 64 4e 62 63 57 55 77 71 57 2e 64 6c 6c } //1 ixIKjbJjaRAddNbcWUwqW.dll
		$a_81_5 = {77 46 75 62 4b 51 41 73 71 69 74 45 70 68 45 6a 63 75 76 6f 48 68 6c 5a 6b } //1 wFubKQAsqitEphEjcuvoHhlZk
		$a_81_6 = {49 56 73 72 76 45 58 51 59 70 73 6c 6c 71 52 62 75 53 69 4c 6c 61 4c 56 63 6c 68 70 } //1 IVsrvEXQYpsllqRbuSiLlaLVclhp
		$a_81_7 = {43 49 57 6e 6c 4e 6c 46 43 50 4d 6e 53 6d 76 5a 6c 78 48 71 67 4d 72 4e 66 65 72 4a 58 2e 64 6c 6c } //1 CIWnlNlFCPMnSmvZlxHqgMrNferJX.dll
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}