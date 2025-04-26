
rule Trojan_Win32_DumpLsass_ZPA{
	meta:
		description = "Trojan:Win32/DumpLsass.ZPA,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {2d 00 61 00 63 00 63 00 65 00 70 00 74 00 65 00 75 00 6c 00 61 00 20 00 2d 00 6d 00 61 00 20 00 6c 00 73 00 61 00 73 00 73 00 2e 00 65 00 78 00 65 00 } //1 -accepteula -ma lsass.exe
		$a_00_1 = {2d 00 61 00 63 00 63 00 65 00 70 00 74 00 65 00 75 00 6c 00 61 00 20 00 2d 00 6d 00 6d 00 20 00 6c 00 73 00 61 00 73 00 73 00 2e 00 65 00 78 00 65 00 } //1 -accepteula -mm lsass.exe
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}