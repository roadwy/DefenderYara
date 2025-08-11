
rule Trojan_Win32_ClickFix_DBT_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DBT!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,ffffff82 00 ffffff82 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_00_1 = {29 00 7c 00 25 00 7b 00 24 00 } //10 )|%{$
		$a_00_2 = {2b 00 3d 00 5b 00 63 00 68 00 61 00 72 00 5d 00 28 00 24 00 5f 00 2b 00 } //10 +=[char]($_+
		$a_00_3 = {29 00 7d 00 3b 00 2e 00 28 00 } //10 )};.(
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10) >=130
 
}