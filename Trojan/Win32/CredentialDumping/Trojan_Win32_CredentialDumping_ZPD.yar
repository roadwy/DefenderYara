
rule Trojan_Win32_CredentialDumping_ZPD{
	meta:
		description = "Trojan:Win32/CredentialDumping.ZPD,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {63 00 6d 00 64 00 6b 00 65 00 79 00 [0-0a] 20 00 2f 00 6c 00 69 00 73 00 74 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}