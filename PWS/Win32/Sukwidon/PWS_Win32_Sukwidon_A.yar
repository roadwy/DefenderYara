
rule PWS_Win32_Sukwidon_A{
	meta:
		description = "PWS:Win32/Sukwidon.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 68 6f 74 6f 28 25 73 2d 25 73 29 00 } //01 00 
		$a_01_1 = {77 69 6e 64 6f 75 73 2e 6b 7a 2f 69 6e 64 65 78 2e 70 68 70 00 } //01 00 
		$a_01_2 = {6d 69 63 72 6f 73 6f 66 69 2e 6f 72 67 2f 69 6e 64 65 78 2e 70 68 70 00 } //01 00 
		$a_01_3 = {73 6d 74 70 5f 73 65 72 76 65 72 3d 25 73 26 73 6d 74 70 5f 70 6f 72 74 3d 25 64 26 73 6d 74 70 5f 75 73 65 72 3d 25 73 26 73 6d 74 70 5f 70 61 73 73 3d 25 73 26 } //01 00  smtp_server=%s&smtp_port=%d&smtp_user=%s&smtp_pass=%s&
		$a_01_4 = {70 6f 70 33 5f 73 65 72 76 65 72 3d 25 73 26 70 6f 70 33 5f 70 6f 72 74 3d 25 64 26 70 6f 70 33 5f 75 73 65 72 3d 25 73 26 70 6f 70 33 5f 70 61 73 73 3d 25 73 26 } //01 00  pop3_server=%s&pop3_port=%d&pop3_user=%s&pop3_pass=%s&
		$a_01_5 = {49 45 3a 50 73 77 50 72 6f 74 65 63 74 65 64 00 } //00 00  䕉债睳牐瑯捥整d
	condition:
		any of ($a_*)
 
}