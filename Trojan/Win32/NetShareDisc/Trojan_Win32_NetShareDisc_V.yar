
rule Trojan_Win32_NetShareDisc_V{
	meta:
		description = "Trojan:Win32/NetShareDisc.V,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 90 02 10 67 00 65 00 74 00 2d 00 73 00 6d 00 62 00 73 00 68 00 61 00 72 00 65 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}