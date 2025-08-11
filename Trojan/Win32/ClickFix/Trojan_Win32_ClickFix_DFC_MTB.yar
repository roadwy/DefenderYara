
rule Trojan_Win32_ClickFix_DFC_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DFC!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,ffffff82 00 ffffff82 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_00_1 = {3d 00 27 00 69 00 65 00 27 00 2b 00 24 00 } //10 ='ie'+$
		$a_00_2 = {3d 00 27 00 69 00 72 00 27 00 2b 00 24 00 } //10 ='ir'+$
		$a_00_3 = {5d 00 3b 00 26 00 24 00 } //10 ];&$
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10) >=130
 
}