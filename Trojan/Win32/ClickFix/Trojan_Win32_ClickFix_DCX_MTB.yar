
rule Trojan_Win32_ClickFix_DCX_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DCX!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,ffffff98 00 ffffff98 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_00_1 = {24 00 61 00 2b 00 24 00 62 00 2b 00 24 00 63 00 2b 00 24 00 64 00 } //50 $a+$b+$c+$d
		$a_00_2 = {4e 00 65 00 77 00 2d 00 4f 00 62 00 6a 00 65 00 63 00 74 00 20 00 4e 00 65 00 74 00 2e 00 57 00 65 00 62 00 43 00 6c 00 69 00 65 00 6e 00 74 00 } //1 New-Object Net.WebClient
		$a_00_3 = {2e 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 46 00 69 00 6c 00 65 00 28 00 24 00 } //1 .DownloadFile($
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*50+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=152
 
}