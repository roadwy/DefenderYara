
rule Trojan_Win32_ClickFix_DDI_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DDI!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,6f 00 6f 00 03 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_00_1 = {7c 00 4f 00 75 00 74 00 2d 00 53 00 74 00 72 00 69 00 6e 00 67 00 } //10 |Out-String
		$a_00_2 = {63 00 75 00 72 00 6c 00 } //1 curl
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1) >=111
 
}
rule Trojan_Win32_ClickFix_DDI_MTB_2{
	meta:
		description = "Trojan:Win32/ClickFix.DDI!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {2e 00 6f 00 70 00 65 00 6e 00 28 00 27 00 47 00 45 00 54 00 27 00 2c 00 24 00 } //1 .open('GET',$
		$a_00_1 = {73 00 65 00 6e 00 64 00 28 00 29 00 } //1 send()
		$a_00_2 = {2e 00 72 00 65 00 73 00 70 00 6f 00 6e 00 73 00 65 00 } //1 .response
		$a_02_3 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-50] 24 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}