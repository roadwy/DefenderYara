
rule Trojan_Win32_CredentialDumping_ZPC{
	meta:
		description = "Trojan:Win32/CredentialDumping.ZPC,SIGNATURE_TYPE_CMDHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {63 00 65 00 72 00 74 00 75 00 74 00 69 00 6c 00 } //1 certutil
		$a_00_1 = {20 00 2d 00 66 00 20 00 } //1  -f 
		$a_00_2 = {20 00 2d 00 76 00 20 00 } //1  -v 
		$a_00_3 = {2d 00 65 00 6e 00 63 00 6f 00 64 00 65 00 68 00 65 00 78 00 } //1 -encodehex
		$a_00_4 = {47 00 4c 00 4f 00 42 00 41 00 4c 00 52 00 4f 00 4f 00 54 00 5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 48 00 61 00 72 00 64 00 64 00 69 00 73 00 6b 00 56 00 6f 00 6c 00 75 00 6d 00 65 00 53 00 68 00 61 00 64 00 6f 00 77 00 43 00 6f 00 70 00 79 00 } //1 GLOBALROOT\Device\HarddiskVolumeShadowCopy
		$a_00_5 = {5c 00 63 00 6f 00 6e 00 66 00 69 00 67 00 5c 00 53 00 41 00 4d 00 } //1 \config\SAM
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}