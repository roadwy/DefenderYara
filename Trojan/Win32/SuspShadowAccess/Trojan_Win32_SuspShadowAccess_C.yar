
rule Trojan_Win32_SuspShadowAccess_C{
	meta:
		description = "Trojan:Win32/SuspShadowAccess.C,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {77 00 69 00 6e 00 33 00 32 00 5f 00 73 00 68 00 61 00 64 00 6f 00 77 00 63 00 6f 00 70 00 79 00 } //fb ff 
		$a_00_1 = {2e 00 63 00 72 00 65 00 61 00 74 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}