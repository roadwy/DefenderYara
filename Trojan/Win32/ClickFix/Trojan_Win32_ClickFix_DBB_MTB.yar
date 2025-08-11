
rule Trojan_Win32_ClickFix_DBB_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DBB!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,ffffff82 00 ffffff82 00 04 00 00 "
		
	strings :
		$a_00_0 = {6d 00 73 00 68 00 74 00 61 00 } //100 mshta
		$a_00_1 = {76 00 62 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 } //10 vbscript:
		$a_00_2 = {43 00 72 00 65 00 61 00 74 00 65 00 4f 00 62 00 6a 00 65 00 63 00 74 00 28 00 } //10 CreateObject(
		$a_00_3 = {77 00 49 00 6e 00 64 00 4f 00 77 00 2e 00 63 00 4c 00 6f 00 53 00 65 00 } //10 wIndOw.cLoSe
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10) >=130
 
}