
rule Trojan_Win32_ClickFix_DED_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DED!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,78 00 78 00 03 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_00_1 = {4e 00 65 00 77 00 2d 00 4f 00 62 00 6a 00 65 00 63 00 74 00 20 00 2d 00 43 00 6f 00 6d 00 4f 00 62 00 6a 00 65 00 63 00 74 00 20 00 57 00 53 00 63 00 72 00 69 00 70 00 74 00 2e 00 53 00 68 00 65 00 6c 00 6c 00 } //10 New-Object -ComObject WScript.Shell
		$a_00_2 = {2e 00 53 00 70 00 65 00 63 00 69 00 61 00 6c 00 46 00 6f 00 6c 00 64 00 65 00 72 00 73 00 28 00 27 00 53 00 74 00 61 00 72 00 74 00 75 00 70 00 27 00 29 00 } //10 .SpecialFolders('Startup')
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10) >=120
 
}