
rule Ransom_Win32_LockScreen_DO{
	meta:
		description = "Ransom:Win32/LockScreen.DO,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {31 00 39 00 32 00 2e 00 31 00 36 00 38 00 2e 00 30 00 2e 00 31 00 30 00 31 00 } //1 192.168.0.101
		$a_01_1 = {57 00 65 00 6c 00 63 00 6f 00 6d 00 65 00 20 00 74 00 6f 00 20 00 79 00 6f 00 75 00 72 00 20 00 73 00 79 00 73 00 74 00 65 00 6d 00 21 00 } //1 Welcome to your system!
		$a_01_2 = {46 3a 5c d0 91 d0 bb d0 be d0 ba d0 b8 d1 80 d0 b0 d1 82 d0 be d1 80 5c d0 91 d0 bb d0 be d0 ba d0 b8 d1 80 d0 b0 d1 82 d0 be d1 80 5c 6f 62 6a 5c 78 38 36 5c 52 65 6c 65 61 73 65 5c d0 91 d0 bb d0 be d0 ba d0 b8 d1 80 d0 b0 d1 82 d0 be d1 80 2e 70 64 62 00 } //1
		$a_01_3 = {57 00 49 00 4e 00 4c 00 4f 00 43 00 4b 00 35 00 35 00 35 00 5c 00 52 00 55 00 42 00 49 00 4e 00 } //1 WINLOCK555\RUBIN
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}