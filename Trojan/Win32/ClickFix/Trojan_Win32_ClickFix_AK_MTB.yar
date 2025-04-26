
rule Trojan_Win32_ClickFix_AK_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.AK!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {77 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 73 00 68 00 65 00 6c 00 6c 00 } //1 wscript.shell
		$a_00_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_2 = {2e 00 73 00 65 00 6e 00 64 00 4b 00 65 00 79 00 73 00 28 00 } //1 .sendKeys(
		$a_00_3 = {66 00 6f 00 72 00 65 00 61 00 63 00 68 00 } //1 foreach
		$a_00_4 = {68 00 74 00 74 00 70 00 } //1 http
		$a_00_5 = {6e 00 65 00 77 00 2d 00 6f 00 62 00 6a 00 65 00 63 00 74 00 } //1 new-object
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}