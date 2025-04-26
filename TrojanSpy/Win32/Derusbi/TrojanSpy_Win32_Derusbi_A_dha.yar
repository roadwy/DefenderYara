
rule TrojanSpy_Win32_Derusbi_A_dha{
	meta:
		description = "TrojanSpy:Win32/Derusbi.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 08 00 00 "
		
	strings :
		$a_01_0 = {4b 00 65 00 79 00 6c 00 6f 00 67 00 20 00 25 00 64 00 20 00 63 00 68 00 61 00 72 00 73 00 } //1 Keylog %d chars
		$a_01_1 = {49 00 45 00 20 00 61 00 63 00 63 00 6f 00 75 00 6e 00 74 00 20 00 25 00 64 00 20 00 66 00 6f 00 75 00 6e 00 64 00 } //1 IE account %d found
		$a_01_2 = {41 00 56 00 3a 00 20 00 25 00 73 00 } //1 AV: %s
		$a_01_3 = {5c 00 7a 00 69 00 70 00 74 00 6d 00 70 00 24 00 } //2 \ziptmp$
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 41 63 63 6f 75 6e 74 20 4d 61 6e 61 67 65 72 5c 41 63 63 6f 75 6e 74 73 } //1 Software\Microsoft\Internet Account Manager\Accounts
		$a_01_5 = {50 4f 53 54 20 2f 43 61 74 65 6c 6f 67 2f 6c 6f 67 69 6e 31 2e 61 73 70 20 48 54 54 50 2f 31 2e 31 } //1 POST /Catelog/login1.asp HTTP/1.1
		$a_01_6 = {5c 73 79 73 74 65 6d 33 32 5c 6d 73 75 73 62 00 2e 64 61 74 } //1 獜獹整㍭尲獭獵b搮瑡
		$a_00_7 = {50 4f 53 54 20 2f 70 68 6f 74 6f 73 2f 70 68 6f 74 6f 2e 61 73 70 20 48 54 54 50 2f 31 2e 31 } //1 POST /photos/photo.asp HTTP/1.1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_00_7  & 1)*1) >=5
 
}