
rule PWS_Win32_PWSteal_K{
	meta:
		description = "PWS:Win32/PWSteal.K,SIGNATURE_TYPE_PEHSTR,19 00 19 00 08 00 00 0a 00 "
		
	strings :
		$a_01_0 = {33 36 30 73 61 66 65 2e 65 78 65 00 33 36 30 74 72 61 79 2e 65 78 65 00 73 61 66 65 62 6f 78 74 72 61 79 2e 65 78 65 00 67 61 6d 65 2e 65 78 65 00 } //0a 00 
		$a_01_1 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //01 00  CreateToolhelp32Snapshot
		$a_01_2 = {48 6f 73 74 3a 20 68 69 2e 62 61 69 64 75 2e 63 6f 6d } //01 00  Host: hi.baidu.com
		$a_01_3 = {26 72 61 6e 6b 3d } //01 00  &rank=
		$a_01_4 = {26 70 77 64 3d } //01 00  &pwd=
		$a_01_5 = {26 75 73 65 72 6e 61 6d 65 3d } //01 00  &username=
		$a_01_6 = {26 73 65 72 76 65 72 3d } //01 00  &server=
		$a_01_7 = {26 62 61 6e 6b 70 61 73 73 77 6f 72 64 3d } //00 00  &bankpassword=
	condition:
		any of ($a_*)
 
}