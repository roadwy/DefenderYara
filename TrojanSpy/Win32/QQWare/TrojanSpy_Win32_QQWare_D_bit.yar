
rule TrojanSpy_Win32_QQWare_D_bit{
	meta:
		description = "TrojanSpy:Win32/QQWare.D!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {35 42 33 38 33 38 46 35 2d 30 43 38 31 2d 34 36 44 39 2d 41 34 43 30 2d 36 45 41 32 38 43 41 33 45 39 34 32 } //1 5B3838F5-0C81-46D9-A4C0-6EA28CA3E942
		$a_01_1 = {73 76 6f 68 6f 73 74 2e 65 78 65 } //1 svohost.exe
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c 33 36 30 73 61 66 63 } //1 Software\Microsoft\Windows\CurrentVersion\Run\360safc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}