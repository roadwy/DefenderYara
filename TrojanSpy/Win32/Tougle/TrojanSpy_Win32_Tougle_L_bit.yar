
rule TrojanSpy_Win32_Tougle_L_bit{
	meta:
		description = "TrojanSpy:Win32/Tougle.L!bit,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {32 04 19 32 c1 42 83 fa 10 88 04 19 75 02 33 d2 41 3b cd 72 e7 } //02 00 
		$a_03_1 = {c7 02 6b 65 72 6e c7 45 90 01 01 65 6c 33 32 c7 45 90 01 01 2e 64 6c 6c ff 55 00 90 00 } //02 00 
		$a_01_2 = {c7 02 6b 65 72 6e c7 45 38 65 6c 33 32 c7 45 3c 2e 64 6c 6c ff 55 00 89 45 54 eb 35 } //01 00 
		$a_01_3 = {00 00 2f 00 63 00 68 00 6b 00 00 00 } //01 00 
		$a_01_4 = {73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 74 6e } //01 00  schtasks /create /tn
		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 } //00 00  Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
	condition:
		any of ($a_*)
 
}