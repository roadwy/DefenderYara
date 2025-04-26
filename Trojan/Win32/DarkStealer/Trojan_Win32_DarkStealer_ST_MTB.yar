
rule Trojan_Win32_DarkStealer_ST_MTB{
	meta:
		description = "Trojan:Win32/DarkStealer.ST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_81_0 = {44 61 72 6b 53 74 65 61 6c 65 72 } //1 DarkStealer
		$a_81_1 = {50 61 73 73 77 6f 72 64 73 5f 45 64 67 65 2e 74 78 74 } //1 Passwords_Edge.txt
		$a_81_2 = {57 69 6e 64 6f 77 73 20 57 65 62 20 50 61 73 73 77 6f 72 64 20 43 72 65 64 65 6e 74 69 61 6c } //1 Windows Web Password Credential
		$a_81_3 = {57 69 6e 64 6f 77 73 20 44 6f 6d 61 69 6e 20 43 65 72 74 69 66 69 63 61 74 65 20 43 72 65 64 65 6e 74 69 61 6c } //1 Windows Domain Certificate Credential
		$a_81_4 = {57 69 6e 64 6f 77 73 20 44 6f 6d 61 69 6e 20 50 61 73 73 77 6f 72 64 20 43 72 65 64 65 6e 74 69 61 6c } //1 Windows Domain Password Credential
		$a_81_5 = {2f 2f 73 65 74 74 69 6e 67 5b 40 6e 61 6d 65 3d 27 50 61 73 73 77 6f 72 64 27 5d 2f 76 61 6c 75 65 } //1 //setting[@name='Password']/value
		$a_81_6 = {5c 50 61 73 73 77 6f 72 64 73 5f 4d 6f 7a 69 6c 6c 61 2e 74 78 74 } //1 \Passwords_Mozilla.txt
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=6
 
}