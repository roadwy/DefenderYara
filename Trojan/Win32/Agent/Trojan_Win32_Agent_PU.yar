
rule Trojan_Win32_Agent_PU{
	meta:
		description = "Trojan:Win32/Agent.PU,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {22 25 73 22 20 2d 68 69 64 65 00 00 22 25 73 22 00 00 00 00 49 6e 73 74 61 6c 6c 65 72 3a 20 44 53 54 2d 44 61 74 65 69 20 25 73 3a 20 25 73 } //1
		$a_01_1 = {43 4d 44 3a 20 67 65 74 2e 2e 2e } //1 CMD: get...
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {63 6f 6e 6e 65 63 74 28 29 3a 20 73 74 61 74 75 73 3d 25 64 } //1 connect(): status=%d
		$a_01_4 = {33 c0 8d 7c 24 20 ab ab ab ab 0f bf 4a 0a 8b 42 0c 8d 7c 24 24 8b 30 8b c1 c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}