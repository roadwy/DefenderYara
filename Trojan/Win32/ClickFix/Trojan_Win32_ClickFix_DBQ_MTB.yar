
rule Trojan_Win32_ClickFix_DBQ_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DBQ!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,ffffff82 00 ffffff82 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_00_1 = {2d 00 55 00 73 00 65 00 42 00 61 00 73 00 69 00 63 00 50 00 61 00 72 00 73 00 69 00 6e 00 67 00 } //10 -UseBasicParsing
		$a_00_2 = {2d 00 6a 00 6f 00 69 00 6e 00 } //10 -join
		$a_00_3 = {2e 00 4c 00 65 00 6e 00 67 00 74 00 68 00 5d 00 } //10 .Length]
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10) >=130
 
}