
rule Backdoor_Win32_Protux_B_dll{
	meta:
		description = "Backdoor:Win32/Protux.B!dll,SIGNATURE_TYPE_PEHSTR,0c 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 4f 53 54 20 68 74 74 70 3a 2f 2f 25 73 3a 25 64 2f 25 73 20 48 54 54 50 2f 31 2e 31 } //1 POST http://%s:%d/%s HTTP/1.1
		$a_01_1 = {48 54 54 50 48 65 61 64 65 72 3a 25 73 2c 6e 52 65 63 76 65 64 3a 25 64 } //1 HTTPHeader:%s,nRecved:%d
		$a_01_2 = {68 6f 6e 67 7a 69 6e 73 74 00 00 00 6a 71 79 2e 64 61 74 00 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*10) >=10
 
}
rule Backdoor_Win32_Protux_B_dll_2{
	meta:
		description = "Backdoor:Win32/Protux.B!dll,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {56 65 72 73 00 00 00 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 00 } //1
		$a_01_1 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 22 25 73 22 2c 54 53 74 61 72 74 55 70 20 30 78 32 32 20 25 73 00 00 25 73 5c 00 25 64 } //1
		$a_01_2 = {57 69 6e 4e 54 20 00 00 2d 4d 69 6e 69 42 75 69 6c 64 00 00 69 74 2e 64 61 74 00 00 7a 71 75 00 5c 68 6f 6e 67 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}