
rule Trojan_Win32_CredentialDumping_ZPE{
	meta:
		description = "Trojan:Win32/CredentialDumping.ZPE,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {6c 00 73 00 61 00 64 00 75 00 6d 00 70 00 3a 00 3a 00 64 00 63 00 73 00 79 00 6e 00 63 00 } //1 lsadump::dcsync
		$a_00_1 = {2f 00 64 00 6f 00 6d 00 61 00 69 00 6e 00 } //1 /domain
		$a_00_2 = {2f 00 75 00 73 00 65 00 72 00 } //1 /user
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}