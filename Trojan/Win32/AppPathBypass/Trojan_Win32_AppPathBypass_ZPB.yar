
rule Trojan_Win32_AppPathBypass_ZPB{
	meta:
		description = "Trojan:Win32/AppPathBypass.ZPB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //1 powershell.exe
		$a_00_1 = {44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 53 00 74 00 72 00 69 00 6e 00 67 00 } //1 DownloadString
		$a_00_2 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 41 00 70 00 70 00 50 00 61 00 74 00 68 00 42 00 79 00 70 00 61 00 73 00 73 00 2e 00 70 00 73 00 31 00 } //1 Invoke-AppPathBypass.ps1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}