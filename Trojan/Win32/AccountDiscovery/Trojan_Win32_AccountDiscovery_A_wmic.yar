
rule Trojan_Win32_AccountDiscovery_A_wmic{
	meta:
		description = "Trojan:Win32/AccountDiscovery.A!wmic,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_02_0 = {77 00 6d 00 69 00 63 00 [0-40] 75 00 73 00 65 00 72 00 61 00 63 00 63 00 6f 00 75 00 6e 00 74 00 } //1
		$a_02_1 = {67 00 65 00 74 00 2d 00 77 00 6d 00 69 00 6f 00 62 00 6a 00 65 00 63 00 74 00 [0-50] 77 00 69 00 6e 00 33 00 32 00 5f 00 75 00 73 00 65 00 72 00 61 00 63 00 63 00 6f 00 75 00 6e 00 74 00 } //1
		$a_02_2 = {67 00 77 00 6d 00 69 00 20 00 [0-50] 77 00 69 00 6e 00 33 00 32 00 5f 00 75 00 73 00 65 00 72 00 61 00 63 00 63 00 6f 00 75 00 6e 00 74 00 } //1
		$a_00_3 = {6e 00 65 00 76 00 65 00 72 00 5f 00 6d 00 61 00 74 00 63 00 68 00 5f 00 74 00 68 00 69 00 73 00 } //-3 never_match_this
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*-3) >=1
 
}
rule Trojan_Win32_AccountDiscovery_A_wmic_2{
	meta:
		description = "Trojan:Win32/AccountDiscovery.A!wmic,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {77 00 6d 00 69 00 63 00 [0-40] 75 00 73 00 65 00 72 00 61 00 63 00 63 00 6f 00 75 00 6e 00 74 00 } //1
		$a_02_1 = {67 00 65 00 74 00 2d 00 77 00 6d 00 69 00 6f 00 62 00 6a 00 65 00 63 00 74 00 [0-50] 77 00 69 00 6e 00 33 00 32 00 5f 00 75 00 73 00 65 00 72 00 61 00 63 00 63 00 6f 00 75 00 6e 00 74 00 } //1
		$a_02_2 = {67 00 77 00 6d 00 69 00 20 00 [0-50] 77 00 69 00 6e 00 33 00 32 00 5f 00 75 00 73 00 65 00 72 00 61 00 63 00 63 00 6f 00 75 00 6e 00 74 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=1
 
}