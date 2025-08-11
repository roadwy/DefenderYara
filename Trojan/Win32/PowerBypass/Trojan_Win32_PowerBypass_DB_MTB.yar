
rule Trojan_Win32_PowerBypass_DB_MTB{
	meta:
		description = "Trojan:Win32/PowerBypass.DB!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,ffffff82 00 ffffff82 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_00_1 = {48 00 74 00 74 00 70 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 } //10 HttpBrowser
		$a_00_2 = {4f 00 70 00 65 00 72 00 61 00 } //10 Opera
		$a_00_3 = {57 00 67 00 65 00 74 00 } //10 Wget
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10) >=130
 
}