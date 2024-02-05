
rule Trojan_Win32_PhantomShell_C{
	meta:
		description = "Trojan:Win32/PhantomShell.C,SIGNATURE_TYPE_CMDHSTR_EXT,0b 00 0b 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 00 73 00 63 00 2e 00 65 00 78 00 65 00 } //0a 00 
		$a_02_1 = {5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 65 00 6d 00 70 00 5c 00 90 02 ff 2e 00 63 00 6d 00 64 00 6c 00 69 00 6e 00 65 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}