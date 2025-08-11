
rule Trojan_Win32_ClickFix_DEX_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DEX!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,79 00 79 00 04 00 00 "
		
	strings :
		$a_00_0 = {50 00 6f 00 77 00 65 00 72 00 53 00 68 00 65 00 6c 00 6c 00 } //100 PowerShell
		$a_00_1 = {69 00 65 00 78 00 20 00 28 00 49 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 52 00 65 00 73 00 74 00 4d 00 65 00 74 00 68 00 6f 00 64 00 } //10 iex (Invoke-RestMethod
		$a_00_2 = {64 00 6d 00 76 00 72 00 66 00 64 00 2e 00 63 00 6f 00 6d 00 } //10 dmvrfd.com
		$a_00_3 = {68 00 74 00 74 00 70 00 } //1 http
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1) >=121
 
}