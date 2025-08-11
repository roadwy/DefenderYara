
rule Trojan_Win32_ClickFix_BBV_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.BBV!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_1 = {3b 00 5b 00 52 00 65 00 66 00 6c 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 5d 00 3a 00 3a 00 4c 00 6f 00 61 00 64 00 57 00 69 00 74 00 68 00 50 00 61 00 72 00 74 00 69 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 28 00 } //1 ;[Reflection.Assembly]::LoadWithPartialName(
		$a_00_2 = {44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 24 00 } //1 DownloadString($
		$a_00_3 = {6e 00 65 00 74 00 2e 00 77 00 65 00 62 00 63 00 6c 00 69 00 65 00 6e 00 74 00 } //1 net.webclient
		$a_00_4 = {68 00 69 00 64 00 64 00 65 00 6e 00 } //1 hidden
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}