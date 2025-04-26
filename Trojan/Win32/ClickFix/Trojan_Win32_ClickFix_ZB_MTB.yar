
rule Trojan_Win32_ClickFix_ZB_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.ZB!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_1 = {63 00 75 00 72 00 6c 00 } //1 curl
		$a_00_2 = {73 00 74 00 61 00 72 00 74 00 2d 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 } //1 start-process
		$a_00_3 = {63 00 73 00 63 00 72 00 69 00 70 00 74 00 } //1 cscript
		$a_00_4 = {76 00 65 00 72 00 69 00 66 00 } //1 verif
		$a_00_5 = {4a 00 6f 00 69 00 6e 00 2d 00 50 00 61 00 74 00 68 00 20 00 24 00 } //1 Join-Path $
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}