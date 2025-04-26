
rule Trojan_Win32_DumpLsass_ZPD{
	meta:
		description = "Trojan:Win32/DumpLsass.ZPD,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {6e 00 61 00 6e 00 6f 00 64 00 75 00 6d 00 70 00 } //1 nanodump
		$a_00_1 = {20 00 2d 00 77 00 20 00 } //1  -w 
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}