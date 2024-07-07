
rule Backdoor_Win32_Sivuxa_B{
	meta:
		description = "Backdoor:Win32/Sivuxa.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {48 6f 6f 6b 49 6e 69 74 00 00 00 00 48 6f 6f 6b 44 6f 6e 65 } //1
		$a_01_1 = {7b 36 34 44 34 35 41 39 33 2d 30 30 44 44 2d 34 31 63 62 2d 41 31 38 37 2d 46 46 30 32 41 31 35 41 45 33 32 42 7d } //1 {64D45A93-00DD-41cb-A187-FF02A15AE32B}
		$a_01_2 = {69 66 20 65 78 69 73 74 20 22 2e 5c 25 73 22 20 67 6f 74 6f 20 3a 6c 6f 6f 70 } //1 if exist ".\%s" goto :loop
		$a_01_3 = {5c 5c 2e 5c 53 49 43 45 00 00 00 00 5c 5c 2e 5c 4e 54 49 43 45 00 00 00 64 6c 69 6e 73 74 68 2e 64 6c 6c } //1
		$a_00_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}