
rule Trojan_Win32_DumpLsass_ZPE{
	meta:
		description = "Trojan:Win32/DumpLsass.ZPE,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {70 00 79 00 70 00 79 00 6b 00 61 00 74 00 7a 00 } //1 pypykatz
		$a_00_1 = {6c 00 69 00 76 00 65 00 20 00 6c 00 73 00 61 00 } //1 live lsa
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}