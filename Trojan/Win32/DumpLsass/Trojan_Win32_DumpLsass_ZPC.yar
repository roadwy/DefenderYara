
rule Trojan_Win32_DumpLsass_ZPC{
	meta:
		description = "Trojan:Win32/DumpLsass.ZPC,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {64 00 75 00 6d 00 70 00 65 00 72 00 74 00 2e 00 65 00 78 00 65 00 } //1 dumpert.exe
	condition:
		((#a_00_0  & 1)*1) >=1
 
}