
rule Trojan_Win32_ClickFix_EEH_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.EEH!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {2e 00 53 00 65 00 6e 00 64 00 4b 00 65 00 79 00 73 00 28 00 5b 00 63 00 68 00 61 00 72 00 5d 00 } //1 .SendKeys([char]
		$a_00_1 = {77 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 73 00 68 00 65 00 6c 00 6c 00 } //1 wscript.shell
		$a_00_2 = {46 00 6f 00 72 00 28 00 24 00 } //1 For($
		$a_00_3 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_4 = {3b 00 20 00 73 00 74 00 61 00 72 00 74 00 } //1 ; start
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
rule Trojan_Win32_ClickFix_EEH_MTB_2{
	meta:
		description = "Trojan:Win32/ClickFix.EEH!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,65 00 65 00 04 00 00 "
		
	strings :
		$a_00_0 = {27 00 69 00 65 00 78 00 27 00 3b 00 26 00 24 00 } //100 'iex';&$
		$a_00_1 = {27 00 69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 65 00 78 00 70 00 72 00 65 00 73 00 73 00 69 00 6f 00 6e 00 27 00 3b 00 26 00 24 00 } //100 'invoke-expression';&$
		$a_00_2 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 57 00 65 00 62 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00 27 00 3b 00 24 00 } //1 Invoke-WebRequest';$
		$a_00_3 = {69 00 77 00 72 00 27 00 3b 00 24 00 } //1 iwr';$
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*100+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=101
 
}