
rule Trojan_Win32_ClickFix_SLFA_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.SLFA!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_02_1 = {2d 00 45 00 50 00 20 00 [0-04] 20 00 2d 00 63 00 20 00 69 00 65 00 78 00 28 00 69 00 72 00 6d 00 } //1
		$a_00_2 = {2e 00 70 00 64 00 66 00 } //1 .pdf
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}