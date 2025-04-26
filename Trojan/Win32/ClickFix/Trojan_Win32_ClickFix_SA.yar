
rule Trojan_Win32_ClickFix_SA{
	meta:
		description = "Trojan:Win32/ClickFix.SA,SIGNATURE_TYPE_CMDHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //10 powershell
		$a_00_1 = {20 00 05 27 20 00 } //10  ✅ 
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10) >=20
 
}