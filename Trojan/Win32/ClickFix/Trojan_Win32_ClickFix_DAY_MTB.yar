
rule Trojan_Win32_ClickFix_DAY_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DAY!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //10 powershell
		$a_00_1 = {2d 00 65 00 6e 00 63 00 } //1 -enc
		$a_00_2 = {2e 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 } //1 .DownloadString(
		$a_00_3 = {4e 00 65 00 77 00 2d 00 4f 00 62 00 6a 00 65 00 63 00 74 00 20 00 4e 00 65 00 74 00 2e 00 57 00 65 00 62 00 43 00 6c 00 69 00 65 00 6e 00 74 00 } //1 New-Object Net.WebClient
		$a_00_4 = {7c 00 69 00 65 00 78 00 } //1 |iex
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=14
 
}