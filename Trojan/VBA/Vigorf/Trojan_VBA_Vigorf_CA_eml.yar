
rule Trojan_VBA_Vigorf_CA_eml{
	meta:
		description = "Trojan:VBA/Vigorf.CA!eml,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {72 65 64 65 66 69 6c 65 70 72 2e 73 73 6c 62 6c 69 6e 64 61 64 6f 2e 63 6f 6d 2f [0-0f] 2e 68 74 61 } //1
		$a_03_1 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a [0-50] 5c 72 6f 6f 74 5c 63 69 6d 76 32 22 29 } //1
		$a_01_2 = {3d 20 6f 62 6a 57 4d 49 53 65 72 76 69 63 65 2e 47 65 74 28 22 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 22 29 } //1 = objWMIService.Get("Win32_Process")
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}