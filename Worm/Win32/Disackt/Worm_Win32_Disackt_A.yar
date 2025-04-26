
rule Worm_Win32_Disackt_A{
	meta:
		description = "Worm:Win32/Disackt.A,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {72 5c 44 69 73 61 43 4b 54 00 52 75 6e 5c 4b 68 6d 65 72 20 56 69 72 75 73 00 6d 73 63 } //4
		$a_01_1 = {00 4d 79 20 43 56 00 } //2
		$a_01_2 = {4b 75 6e 74 68 79 00 00 4d 6f 64 65 6c 31 } //2
		$a_01_3 = {52 65 67 53 65 74 56 61 6c 75 65 45 78 41 } //1 RegSetValueExA
		$a_01_4 = {53 65 74 57 69 6e 64 6f 77 54 65 78 74 41 } //1 SetWindowTextA
		$a_01_5 = {50 6f 73 74 4d 65 73 73 61 67 65 41 } //1 PostMessageA
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=10
 
}