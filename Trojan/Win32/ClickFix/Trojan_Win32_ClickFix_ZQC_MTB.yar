
rule Trojan_Win32_ClickFix_ZQC_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.ZQC!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,69 00 69 00 05 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_00_1 = {41 00 63 00 74 00 69 00 76 00 65 00 58 00 4f 00 62 00 6a 00 65 00 63 00 74 00 } //5 ActiveXObject
		$a_00_2 = {2e 00 49 00 6e 00 73 00 65 00 72 00 74 00 28 00 } //5 .Insert(
		$a_00_3 = {76 62 73 63 72 69 70 74 3a 45 78 65 63 75 74 65 28 } //5 vbscript:Execute(
		$a_00_4 = {3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 } //5 ::FromBase64String
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*5+(#a_00_2  & 1)*5+(#a_00_3  & 1)*5+(#a_00_4  & 1)*5) >=105
 
}