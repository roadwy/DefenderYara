
rule Trojan_Win32_suspRemoteCopy_SA{
	meta:
		description = "Trojan:Win32/suspRemoteCopy.SA,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 } //01 00  cmd
		$a_00_1 = {20 00 63 00 6f 00 70 00 79 00 20 00 } //01 00   copy 
		$a_00_2 = {5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 65 00 6d 00 70 00 5c 00 } //00 00  \windows\temp\
	condition:
		any of ($a_*)
 
}