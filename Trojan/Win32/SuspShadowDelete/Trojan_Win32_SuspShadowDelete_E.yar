
rule Trojan_Win32_SuspShadowDelete_E{
	meta:
		description = "Trojan:Win32/SuspShadowDelete.E,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {77 00 69 00 6e 00 33 00 32 00 5f 00 73 00 68 00 61 00 64 00 6f 00 77 00 63 00 6f 00 70 00 79 00 } //01 00  win32_shadowcopy
		$a_00_1 = {64 00 65 00 6c 00 65 00 74 00 65 00 } //fb ff  delete
		$a_00_2 = {2e 00 63 00 72 00 65 00 61 00 74 00 65 00 } //00 00  .create
	condition:
		any of ($a_*)
 
}