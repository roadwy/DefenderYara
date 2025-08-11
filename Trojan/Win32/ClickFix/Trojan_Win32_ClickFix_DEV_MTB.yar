
rule Trojan_Win32_ClickFix_DEV_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DEV!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,ffffff82 00 ffffff82 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_00_1 = {5b 00 63 00 68 00 61 00 72 00 5d 00 5b 00 63 00 6f 00 6e 00 76 00 65 00 72 00 74 00 5d 00 3a 00 3a 00 54 00 6f 00 49 00 6e 00 74 00 33 00 32 00 28 00 24 00 } //10 [char][convert]::ToInt32($
		$a_00_2 = {5b 00 53 00 63 00 72 00 69 00 70 00 74 00 42 00 6c 00 6f 00 63 00 6b 00 5d 00 3a 00 3a 00 43 00 72 00 65 00 61 00 74 00 65 00 28 00 } //10 [ScriptBlock]::Create(
		$a_00_3 = {29 00 7c 00 25 00 7b 00 } //10 )|%{
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10) >=130
 
}