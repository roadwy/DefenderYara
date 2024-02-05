
rule Trojan_Win32_BlockMpTamperProtectedContent_B{
	meta:
		description = "Trojan:Win32/BlockMpTamperProtectedContent.B,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {6d 00 6b 00 6c 00 69 00 6e 00 6b 00 90 02 80 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 64 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 3a 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}