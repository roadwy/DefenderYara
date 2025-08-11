
rule Trojan_Win32_ClickFix_DCZ_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DCZ!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,6f 00 6f 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_00_1 = {53 00 74 00 61 00 72 00 74 00 2d 00 42 00 69 00 74 00 73 00 54 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 20 00 28 00 } //10 Start-BitsTransfer (
		$a_00_2 = {53 00 74 00 61 00 72 00 74 00 2d 00 27 00 42 00 69 00 74 00 73 00 54 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 27 00 20 00 28 00 } //10 Start-'BitsTransfer' (
		$a_00_3 = {24 00 65 00 6e 00 76 00 3a 00 54 00 45 00 4d 00 50 00 2b 00 27 00 } //1 $env:TEMP+'
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1) >=111
 
}