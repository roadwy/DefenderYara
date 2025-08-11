
rule Trojan_Win32_ClickFix_DGS_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DGS!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,ffffff82 00 ffffff82 00 04 00 00 "
		
	strings :
		$a_02_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-50] 24 00 } //100
		$a_00_1 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 20 00 2f 00 74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 20 00 24 00 } //10 bitsadmin /transfer $
		$a_00_2 = {2d 00 6a 00 6f 00 69 00 6e 00 28 00 24 00 65 00 6e 00 76 00 3a 00 54 00 45 00 4d 00 50 00 } //10 -join($env:TEMP
		$a_00_3 = {3b 00 26 00 28 00 24 00 } //10 ;&($
	condition:
		((#a_02_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10) >=130
 
}