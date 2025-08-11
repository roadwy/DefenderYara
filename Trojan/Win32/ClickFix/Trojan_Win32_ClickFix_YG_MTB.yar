
rule Trojan_Win32_ClickFix_YG_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.YG!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //10 powershell
		$a_00_1 = {69 00 65 00 78 00 28 00 69 00 72 00 6d 00 28 00 24 00 } //10 iex(irm($
		$a_00_2 = {2e 00 54 00 6f 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 29 00 } //10 .ToString()
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10) >=30
 
}