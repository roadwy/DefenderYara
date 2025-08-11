
rule Trojan_Win32_ClickFix_DGX_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DGX!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,6f 00 6f 00 04 00 00 "
		
	strings :
		$a_02_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-50] 24 00 } //100
		$a_00_1 = {64 00 6c 00 3d 00 31 00 3b 00 20 00 69 00 65 00 78 00 20 00 24 00 } //10 dl=1; iex $
		$a_00_2 = {64 00 6c 00 3d 00 31 00 3b 00 20 00 69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 65 00 78 00 70 00 72 00 65 00 73 00 73 00 69 00 6f 00 6e 00 20 00 24 00 } //10 dl=1; invoke-expression $
		$a_00_3 = {3d 00 20 00 69 00 77 00 72 00 } //1 = iwr
	condition:
		((#a_02_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1) >=111
 
}