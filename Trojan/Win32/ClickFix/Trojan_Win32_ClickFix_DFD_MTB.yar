
rule Trojan_Win32_ClickFix_DFD_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DFD!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,ffffff82 00 ffffff82 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_00_1 = {2e 00 6d 00 73 00 69 00 3b 00 20 00 6d 00 73 00 69 00 65 00 78 00 65 00 63 00 20 00 2f 00 69 00 20 00 24 00 65 00 6e 00 76 00 3a 00 54 00 45 00 4d 00 50 00 } //10 .msi; msiexec /i $env:TEMP
		$a_00_2 = {2e 00 6d 00 73 00 69 00 20 00 2f 00 71 00 62 00 } //10 .msi /qb
		$a_00_3 = {69 00 77 00 72 00 20 00 68 00 74 00 74 00 70 00 } //10 iwr http
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10) >=130
 
}