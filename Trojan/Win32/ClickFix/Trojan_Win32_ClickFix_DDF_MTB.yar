
rule Trojan_Win32_ClickFix_DDF_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DDF!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,64 00 64 00 01 00 00 "
		
	strings :
		$a_02_0 = {6d 00 73 00 68 00 74 00 61 00 [0-0f] 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 [0-3c] 3f 00 } //100
	condition:
		((#a_02_0  & 1)*100) >=100
 
}
rule Trojan_Win32_ClickFix_DDF_MTB_2{
	meta:
		description = "Trojan:Win32/ClickFix.DDF!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 00 74 00 61 00 72 00 74 00 2d 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 } //1 Start-Process
		$a_00_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 79 00 6f 00 75 00 74 00 75 00 } //1 https://youtu
		$a_00_2 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_3 = {68 00 69 00 64 00 64 00 65 00 6e 00 } //1 hidden
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}