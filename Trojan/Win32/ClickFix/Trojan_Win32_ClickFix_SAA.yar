
rule Trojan_Win32_ClickFix_SAA{
	meta:
		description = "Trojan:Win32/ClickFix.SAA,SIGNATURE_TYPE_CMDHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_00_0 = {6d 00 73 00 68 00 74 00 61 00 } //10 mshta
		$a_00_1 = {20 00 05 27 20 00 } //10  ✅ 
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10) >=20
 
}