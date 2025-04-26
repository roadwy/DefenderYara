
rule Trojan_Win32_CredentialDumping_ZPF{
	meta:
		description = "Trojan:Win32/CredentialDumping.ZPF,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {67 00 73 00 65 00 63 00 64 00 75 00 6d 00 70 00 [0-0a] 20 00 2d 00 61 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}