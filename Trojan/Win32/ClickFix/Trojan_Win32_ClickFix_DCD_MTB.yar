
rule Trojan_Win32_ClickFix_DCD_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DCD!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,ffffff83 00 ffffff83 00 06 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_00_1 = {24 00 65 00 6e 00 76 00 3a 00 74 00 6d 00 70 00 } //10 $env:tmp
		$a_00_2 = {45 00 78 00 70 00 61 00 6e 00 64 00 2d 00 41 00 72 00 63 00 68 00 69 00 76 00 65 00 } //10 Expand-Archive
		$a_00_3 = {2d 00 46 00 6f 00 72 00 63 00 65 00 } //10 -Force
		$a_00_4 = {69 00 72 00 6d 00 20 00 2d 00 55 00 72 00 69 00 } //1 irm -Uri
		$a_00_5 = {69 00 77 00 72 00 20 00 2d 00 55 00 72 00 69 00 } //1 iwr -Uri
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=131
 
}