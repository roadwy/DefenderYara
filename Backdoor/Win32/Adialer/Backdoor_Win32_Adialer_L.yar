
rule Backdoor_Win32_Adialer_L{
	meta:
		description = "Backdoor:Win32/Adialer.L,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 63 67 69 2d 62 69 6e 2f 72 65 64 69 72 2e 70 6c 3f 69 64 3d 25 64 26 65 6e 74 72 79 3d 25 64 26 73 69 74 65 3d 25 64 } //3 /cgi-bin/redir.pl?id=%d&entry=%d&site=%d
		$a_01_1 = {73 6f 66 74 77 61 72 65 5c 69 6e 74 65 72 62 69 6c 6c 5c 65 7a 2d 31 2d 32 2d 33 5c 70 72 65 66 73 } //4 software\interbill\ez-1-2-3\prefs
		$a_01_2 = {50 6c 65 61 73 65 20 45 2d 4d 61 69 6c 20 73 75 70 70 6f 72 74 40 65 7a 6e 65 74 2e 63 6f 2e 75 6b 20 66 6f 72 20 61 73 73 69 73 74 61 6e 63 65 2e } //2 Please E-Mail support@eznet.co.uk for assistance.
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*4+(#a_01_2  & 1)*2) >=9
 
}