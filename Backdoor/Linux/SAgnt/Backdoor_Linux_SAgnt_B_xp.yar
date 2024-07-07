
rule Backdoor_Linux_SAgnt_B_xp{
	meta:
		description = "Backdoor:Linux/SAgnt.B!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 4f 53 54 20 2f 77 61 6e 69 70 63 6e 2e 78 6d 6c 20 48 54 54 50 2f 31 2e 31 } //1 POST /wanipcn.xml HTTP/1.1
		$a_01_1 = {63 7a 32 69 73 67 39 6c 38 75 37 62 35 78 77 30 6d 72 36 6a 68 66 76 70 6b 74 65 79 6f 33 6e 61 64 71 31 34 } //1 cz2isg9l8u7b5xw0mr6jhfvpkteyo3nadq14
		$a_01_2 = {50 4f 53 54 20 2f 63 67 69 2d 62 69 6e 2f 6c 6f 67 69 6e 5f 61 63 74 69 6f 6e 2e 63 67 69 20 48 54 54 50 2f 31 2e 31 } //1 POST /cgi-bin/login_action.cgi HTTP/1.1
		$a_01_3 = {48 6f 73 74 3a 20 31 32 37 2e 30 2e 30 2e 31 3a 35 32 38 36 39 } //1 Host: 127.0.0.1:52869
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}