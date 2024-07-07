
rule TrojanSpy_Win32_Broler_B_dha{
	meta:
		description = "TrojanSpy:Win32/Broler.B!dha,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 72 6f 6a 65 63 74 73 5c 61 76 65 6e 67 65 72 5c 52 65 6c 65 61 73 65 5c 61 76 65 6e 67 65 72 2e 70 64 62 } //1 Projects\avenger\Release\avenger.pdb
		$a_01_1 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {77 00 69 00 6e 00 6c 00 6f 00 67 00 69 00 6e 00 2e 00 65 00 78 00 65 00 } //1 winlogin.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}