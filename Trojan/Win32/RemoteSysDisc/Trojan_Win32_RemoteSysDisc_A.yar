
rule Trojan_Win32_RemoteSysDisc_A{
	meta:
		description = "Trojan:Win32/RemoteSysDisc.A,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //02 00 
		$a_00_1 = {67 00 65 00 74 00 2d 00 61 00 64 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 } //00 00 
	condition:
		any of ($a_*)
 
}