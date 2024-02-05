
rule Trojan_Win32_HLinkOverride_A_winbio{
	meta:
		description = "Trojan:Win32/HLinkOverride.A!winbio,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 90 02 50 6d 00 6b 00 6c 00 69 00 6e 00 6b 00 90 00 } //01 00 
		$a_02_1 = {6d 00 6b 00 6c 00 69 00 6e 00 6b 00 90 02 50 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 77 00 69 00 6e 00 62 00 69 00 6f 00 2e 00 64 00 6c 00 6c 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}