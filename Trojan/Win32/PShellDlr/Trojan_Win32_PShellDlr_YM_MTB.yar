
rule Trojan_Win32_PShellDlr_YM_MTB{
	meta:
		description = "Trojan:Win32/PShellDlr.YM!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,28 00 28 00 04 00 00 "
		
	strings :
		$a_00_0 = {2d 00 73 00 70 00 6c 00 69 00 74 00 } //10 -split
		$a_00_1 = {63 00 68 00 61 00 72 00 5d 00 28 00 5b 00 63 00 6f 00 6e 00 76 00 65 00 72 00 74 00 5d 00 3a 00 3a 00 54 00 6f 00 49 00 6e 00 74 00 33 00 32 00 28 00 24 00 5f 00 } //10 char]([convert]::ToInt32($_
		$a_00_2 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //10 powershell
		$a_00_3 = {2d 00 6a 00 6f 00 69 00 6e 00 } //10 -join
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10) >=40
 
}