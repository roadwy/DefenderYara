
rule Trojan_Win32_ClickFix_DHJ_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DHJ!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,ffffff83 00 ffffff83 00 06 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_00_1 = {77 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 73 00 68 00 65 00 6c 00 6c 00 } //10 wscript.shell
		$a_00_2 = {6e 00 65 00 77 00 2d 00 6f 00 62 00 6a 00 65 00 63 00 74 00 20 00 2d 00 63 00 6f 00 6d 00 } //10 new-object -com
		$a_00_3 = {2e 00 53 00 65 00 6e 00 64 00 4b 00 65 00 79 00 73 00 28 00 } //10 .SendKeys(
		$a_00_4 = {66 00 6f 00 72 00 20 00 28 00 } //1 for (
		$a_00_5 = {77 00 68 00 69 00 6c 00 65 00 28 00 } //1 while(
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=131
 
}