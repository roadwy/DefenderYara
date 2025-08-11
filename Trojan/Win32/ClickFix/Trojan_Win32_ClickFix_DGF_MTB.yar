
rule Trojan_Win32_ClickFix_DGF_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DGF!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,78 00 78 00 03 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_00_1 = {53 00 74 00 61 00 72 00 74 00 2d 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 27 00 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 } //10 Start-Process 'https://
		$a_00_2 = {3f 00 73 00 75 00 62 00 69 00 64 00 3d 00 } //10 ?subid=
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10) >=120
 
}