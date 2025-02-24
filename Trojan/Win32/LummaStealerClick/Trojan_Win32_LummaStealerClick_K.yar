
rule Trojan_Win32_LummaStealerClick_K{
	meta:
		description = "Trojan:Win32/LummaStealerClick.K,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_1 = {68 00 69 00 64 00 64 00 65 00 6e 00 } //1 hidden
		$a_00_2 = {69 00 77 00 72 00 20 00 68 00 74 00 74 00 70 00 } //1 iwr http
		$a_00_3 = {2e 00 70 00 73 00 31 00 20 00 7c 00 20 00 69 00 65 00 78 00 } //1 .ps1 | iex
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}