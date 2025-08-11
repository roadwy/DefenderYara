
rule Trojan_Win32_ClickFix_EEE_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.EEE!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_02_1 = {2e 00 74 00 78 00 74 00 [0-10] 7c 00 20 00 69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 65 00 78 00 70 00 72 00 65 00 73 00 73 00 69 00 6f 00 6e 00 } //1
		$a_00_2 = {68 00 74 00 74 00 70 00 } //1 http
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}