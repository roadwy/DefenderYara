
rule Trojan_Win32_ClickFix_SIAA{
	meta:
		description = "Trojan:Win32/ClickFix.SIAA,SIGNATURE_TYPE_CMDHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {63 00 6d 00 64 00 [0-10] 2f 00 63 00 [0-30] 6d 00 73 00 68 00 74 00 61 00 } //10
		$a_00_1 = {68 00 74 00 74 00 70 00 } //10 http
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10) >=20
 
}