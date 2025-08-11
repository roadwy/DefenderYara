
rule Trojan_Win32_ClickFix_DGY_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DGY!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,79 00 79 00 05 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_00_1 = {2e 00 70 00 68 00 70 00 27 00 3b 00 24 00 } //10 .php';$
		$a_00_2 = {3d 00 27 00 69 00 77 00 27 00 3b 00 24 00 } //10 ='iw';$
		$a_00_3 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 45 00 78 00 70 00 72 00 65 00 73 00 73 00 69 00 6f 00 6e 00 20 00 24 00 } //1 Invoke-Expression $
		$a_00_4 = {69 00 65 00 78 00 20 00 24 00 } //1 iex $
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=121
 
}