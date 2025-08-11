
rule Trojan_Win32_ClickFix_HI_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.HI!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,65 00 65 00 03 00 00 "
		
	strings :
		$a_00_0 = {7c 00 69 00 65 00 78 00 20 00 23 00 } //100 |iex #
		$a_00_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_2 = {6d 00 73 00 68 00 74 00 61 00 } //1 mshta
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=101
 
}