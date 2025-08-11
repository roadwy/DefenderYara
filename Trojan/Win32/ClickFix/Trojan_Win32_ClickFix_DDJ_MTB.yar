
rule Trojan_Win32_ClickFix_DDJ_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DDJ!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {26 00 26 00 20 00 66 00 74 00 70 00 } //1 && ftp
		$a_00_1 = {26 00 26 00 20 00 63 00 75 00 72 00 6c 00 } //1 && curl
		$a_00_2 = {68 00 74 00 74 00 70 00 } //1 http
		$a_00_3 = {73 00 65 00 72 00 76 00 69 00 63 00 65 00 } //1 service
		$a_00_4 = {2e 00 6c 00 6f 00 67 00 } //1 .log
		$a_00_5 = {6d 00 73 00 65 00 64 00 67 00 65 00 77 00 65 00 62 00 76 00 69 00 65 00 77 00 32 00 2e 00 65 00 78 00 65 00 } //-100 msedgewebview2.exe
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*-100) >=5
 
}
rule Trojan_Win32_ClickFix_DDJ_MTB_2{
	meta:
		description = "Trojan:Win32/ClickFix.DDJ!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,79 00 79 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_00_1 = {5b 00 73 00 63 00 72 00 69 00 70 00 74 00 62 00 6c 00 6f 00 63 00 6b 00 5d 00 3a 00 3a 00 43 00 72 00 65 00 61 00 74 00 65 00 28 00 } //10 [scriptblock]::Create(
		$a_00_2 = {47 00 65 00 74 00 2d 00 43 00 6c 00 69 00 70 00 62 00 6f 00 61 00 72 00 64 00 29 00 20 00 2d 00 6a 00 6f 00 69 00 6e 00 } //10 Get-Clipboard) -join
		$a_00_3 = {7c 00 20 00 63 00 6c 00 69 00 70 00 3b 00 20 00 26 00 } //1 | clip; &
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1) >=121
 
}