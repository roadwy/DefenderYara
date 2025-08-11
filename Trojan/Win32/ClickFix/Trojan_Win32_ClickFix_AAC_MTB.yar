
rule Trojan_Win32_ClickFix_AAC_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.AAC!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_1 = {72 00 61 00 77 00 2e 00 67 00 69 00 74 00 68 00 75 00 62 00 } //1 raw.github
		$a_00_2 = {53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 50 00 72 00 6f 00 74 00 6f 00 63 00 6f 00 6c 00 } //-100 SecurityProtocol
		$a_00_3 = {53 00 65 00 72 00 76 00 69 00 63 00 65 00 50 00 6f 00 69 00 6e 00 74 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 } //-100 ServicePointManager
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*-100+(#a_00_3  & 1)*-100) >=2
 
}