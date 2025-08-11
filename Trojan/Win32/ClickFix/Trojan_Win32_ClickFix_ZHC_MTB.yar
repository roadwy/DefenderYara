
rule Trojan_Win32_ClickFix_ZHC_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.ZHC!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {41 00 63 00 74 00 69 00 76 00 65 00 58 00 4f 00 62 00 6a 00 65 00 63 00 74 00 28 00 } //1 ActiveXObject(
		$a_00_1 = {2e 00 2e 00 72 00 65 00 76 00 65 00 72 00 73 00 65 00 } //1 ..reverse
		$a_00_2 = {2e 00 73 00 70 00 6c 00 69 00 74 00 28 00 } //1 .split(
		$a_00_3 = {2e 00 6a 00 6f 00 69 00 6e 00 28 00 } //1 .join(
		$a_00_4 = {3b 00 65 00 76 00 61 00 6c 00 28 00 } //1 ;eval(
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}