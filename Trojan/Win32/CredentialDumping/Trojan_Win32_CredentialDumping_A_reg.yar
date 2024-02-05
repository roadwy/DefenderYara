
rule Trojan_Win32_CredentialDumping_A_reg{
	meta:
		description = "Trojan:Win32/CredentialDumping.A!reg,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 05 00 00 fffffff6 ffffffff "
		
	strings :
		$a_00_0 = {72 00 65 00 67 00 62 00 61 00 63 00 6b 00 75 00 70 00 33 00 } //f6 ff 
		$a_00_1 = {5c 00 72 00 61 00 70 00 69 00 64 00 37 00 5c 00 } //01 00 
		$a_00_2 = {72 00 65 00 67 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_00_3 = {20 00 73 00 61 00 76 00 65 00 20 00 68 00 6b 00 6c 00 6d 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 20 00 } //01 00 
		$a_00_4 = {20 00 5c 00 5c 00 74 00 73 00 63 00 6c 00 69 00 65 00 6e 00 74 00 5c 00 } //00 00 
	condition:
		any of ($a_*)
 
}