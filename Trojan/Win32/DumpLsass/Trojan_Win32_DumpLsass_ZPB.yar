
rule Trojan_Win32_DumpLsass_ZPB{
	meta:
		description = "Trojan:Win32/DumpLsass.ZPB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 } //1 rundll32
		$a_02_1 = {64 00 75 00 6d 00 70 00 65 00 72 00 74 00 2e 00 64 00 6c 00 6c 00 2c 00 [0-04] 64 00 75 00 6d 00 70 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}