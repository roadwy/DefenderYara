
rule Trojan_Win32_CredentialDumping_ZPB{
	meta:
		description = "Trojan:Win32/CredentialDumping.ZPB,SIGNATURE_TYPE_CMDHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_00_0 = {65 00 73 00 65 00 6e 00 74 00 75 00 74 00 6c 00 90 00 02 00 0a 00 20 00 2f 00 79 00 20 00 2f 00 76 00 73 00 73 00 } //10
		$a_00_1 = {5c 00 63 00 6f 00 6e 00 66 00 69 00 67 00 5c 00 53 00 41 00 4d 00 } //1 \config\SAM
		$a_00_2 = {2f 00 63 00 6f 00 6e 00 66 00 69 00 67 00 2f 00 53 00 41 00 4d 00 } //1 /config/SAM
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=11
 
}