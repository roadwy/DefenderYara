
rule Trojan_Win32_ClickFix_SKJ{
	meta:
		description = "Trojan:Win32/ClickFix.SKJ,SIGNATURE_TYPE_CMDHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_00_0 = {66 00 6f 00 72 00 66 00 69 00 6c 00 65 00 73 00 } //10 forfiles
		$a_00_1 = {63 00 6d 00 64 00 20 00 2f 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 6d 00 73 00 68 00 74 00 61 00 } //10 cmd /c start mshta
		$a_00_2 = {63 00 6d 00 64 00 20 00 2f 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //10 cmd /c start powershell
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10) >=20
 
}