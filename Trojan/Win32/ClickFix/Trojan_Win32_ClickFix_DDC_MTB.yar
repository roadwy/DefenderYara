
rule Trojan_Win32_ClickFix_DDC_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DDC!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,79 00 79 00 05 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_00_1 = {57 00 53 00 63 00 72 00 69 00 70 00 74 00 } //10 WScript
		$a_00_2 = {2e 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 46 00 69 00 6c 00 65 00 28 00 24 00 } //10 .DownloadFile($
		$a_00_3 = {3d 00 24 00 65 00 6e 00 76 00 3a 00 74 00 65 00 6d 00 70 00 2b 00 } //1 =$env:temp+
		$a_00_4 = {3d 00 4a 00 6f 00 69 00 6e 00 2d 00 50 00 61 00 74 00 68 00 20 00 24 00 65 00 6e 00 76 00 3a 00 54 00 45 00 4d 00 50 00 } //1 =Join-Path $env:TEMP
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=121
 
}
rule Trojan_Win32_ClickFix_DDC_MTB_2{
	meta:
		description = "Trojan:Win32/ClickFix.DDC!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,66 00 66 00 04 00 00 "
		
	strings :
		$a_00_0 = {68 00 74 00 74 00 70 00 } //1 http
		$a_00_1 = {2d 00 4d 00 65 00 74 00 68 00 6f 00 64 00 20 00 50 00 6f 00 73 00 74 00 29 00 2e 00 43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 } //100 -Method Post).Content
		$a_00_2 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 45 00 78 00 70 00 72 00 65 00 73 00 73 00 69 00 6f 00 6e 00 28 00 49 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 57 00 65 00 62 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00 20 00 2d 00 } //1 Invoke-Expression(Invoke-WebRequest -
		$a_00_3 = {69 00 65 00 78 00 28 00 49 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 57 00 65 00 62 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00 20 00 2d 00 } //1 iex(Invoke-WebRequest -
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*100+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=102
 
}