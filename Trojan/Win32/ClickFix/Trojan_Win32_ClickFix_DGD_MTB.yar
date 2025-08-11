
rule Trojan_Win32_ClickFix_DGD_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DGD!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,70 00 70 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_00_1 = {2e 00 70 00 73 00 31 00 27 00 3b 00 69 00 65 00 78 00 28 00 24 00 } //10 .ps1';iex($
		$a_00_2 = {4e 00 65 00 74 00 2e 00 57 00 65 00 62 00 43 00 6c 00 69 00 65 00 6e 00 74 00 } //1 Net.WebClient
		$a_00_3 = {44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 24 00 } //1 DownloadString($
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=112
 
}