
rule Trojan_Win32_GuLoader_RSM_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RSM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {53 74 61 74 65 72 20 42 72 6f 73 2e 20 48 6f 6c 64 69 6e 67 73 20 49 6e 63 2e } //1 Stater Bros. Holdings Inc.
		$a_81_1 = {56 69 61 63 6f 6d 20 49 6e 63 } //1 Viacom Inc
		$a_81_2 = {4d 65 61 64 57 65 73 74 76 61 63 6f 20 43 6f 72 70 6f 72 61 74 69 6f 6e } //1 MeadWestvaco Corporation
		$a_81_3 = {6b 75 6e 64 65 62 72 65 76 65 74 2e 65 78 65 } //1 kundebrevet.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Trojan_Win32_GuLoader_RSM_MTB_2{
	meta:
		description = "Trojan:Win32/GuLoader.RSM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {44 72 65 79 65 72 27 73 20 47 72 61 6e 64 20 49 63 65 20 43 72 65 61 6d 2c 20 49 6e 63 2e } //1 Dreyer's Grand Ice Cream, Inc.
		$a_81_1 = {4c 65 6e 6e 6f 78 20 49 6e 74 65 72 6e 61 74 69 6f 6e 61 6c 20 49 6e 63 2e } //1 Lennox International Inc.
		$a_81_2 = {4b 65 6c 6c 6f 67 67 20 43 6f 6d 70 61 6e 79 } //1 Kellogg Company
		$a_81_3 = {42 61 72 6e 65 73 20 26 20 4e 6f 62 6c 65 2c 20 49 6e 63 2e } //1 Barnes & Noble, Inc.
		$a_81_4 = {69 6e 76 69 67 69 6c 61 74 65 20 68 61 76 65 61 72 6b 69 74 65 6b 74 65 72 2e 65 78 65 } //1 invigilate havearkitekter.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}