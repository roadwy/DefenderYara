
rule Trojan_Win32_UACBypassHiddenProc_A{
	meta:
		description = "Trojan:Win32/UACBypassHiddenProc.A,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 90 02 20 73 00 74 00 61 00 72 00 74 00 90 02 30 2f 00 6d 00 69 00 6e 00 90 00 } //01 00 
		$a_02_1 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 90 02 20 73 00 74 00 61 00 72 00 74 00 90 02 30 2f 00 64 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}