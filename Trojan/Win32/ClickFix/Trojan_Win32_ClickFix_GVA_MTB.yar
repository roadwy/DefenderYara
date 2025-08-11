
rule Trojan_Win32_ClickFix_GVA_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.GVA!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,0d 00 0d 00 03 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //5 powershell
		$a_02_1 = {69 00 72 00 6d 00 20 00 [0-ff] 3a 00 [0-0a] 2f 00 24 00 } //5
		$a_00_2 = {69 00 65 00 78 00 } //3 iex
	condition:
		((#a_00_0  & 1)*5+(#a_02_1  & 1)*5+(#a_00_2  & 1)*3) >=13
 
}