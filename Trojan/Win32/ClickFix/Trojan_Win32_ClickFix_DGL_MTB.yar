
rule Trojan_Win32_ClickFix_DGL_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DGL!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,78 00 78 00 03 00 00 "
		
	strings :
		$a_00_0 = {3d 00 22 00 24 00 65 00 6e 00 76 00 3a 00 54 00 45 00 4d 00 50 00 5c 00 24 00 28 00 } //100 ="$env:TEMP\$(
		$a_00_1 = {2e 00 64 00 6f 00 66 00 27 00 3b 00 24 00 } //10 .dof';$
		$a_00_2 = {69 00 77 00 72 00 20 00 24 00 } //10 iwr $
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10) >=120
 
}