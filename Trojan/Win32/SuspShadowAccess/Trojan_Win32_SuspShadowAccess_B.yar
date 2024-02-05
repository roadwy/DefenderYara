
rule Trojan_Win32_SuspShadowAccess_B{
	meta:
		description = "Trojan:Win32/SuspShadowAccess.B,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {77 00 69 00 6e 00 33 00 32 00 5f 00 73 00 68 00 61 00 64 00 6f 00 77 00 63 00 6f 00 70 00 79 00 } //00 00 
	condition:
		any of ($a_*)
 
}