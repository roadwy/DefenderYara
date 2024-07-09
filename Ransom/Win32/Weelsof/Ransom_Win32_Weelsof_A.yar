
rule Ransom_Win32_Weelsof_A{
	meta:
		description = "Ransom:Win32/Weelsof.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_00_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e } //1 SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
		$a_00_2 = {65 78 74 65 72 6e 61 6c 5f 69 70 5f 66 69 6c 65 5f 6e 61 6d 65 } //1 external_ip_file_name
		$a_00_3 = {65 78 70 6c 6f 72 65 72 5f 6e 65 77 2e 65 78 65 } //1 explorer_new.exe
		$a_02_4 = {64 69 6c 6c 79 2f [0-10] 2e 70 68 70 } //1
		$a_00_5 = {b8 01 00 00 00 2b c1 89 44 24 1c b8 02 00 00 00 8b d1 2b c2 89 44 24 18 b8 03 00 00 00 83 c4 08 33 f6 2b c1 89 44 24 08 33 d2 8b c6 f7 f7 8b 44 24 14 8d 8c 34 e8 00 00 00 03 c1 83 c6 04 0f b6 14 1a 00 11 33 d2 f7 f7 8b 44 24 10 03 c1 0f b6 14 1a 00 51 01 33 d2 } //1
		$a_00_6 = {8a 16 8a ca 80 e2 0f c0 e9 04 80 f9 09 53 0f 9e c3 fe cb 80 e3 07 80 c3 30 02 d9 80 fa 09 0f 9e c1 fe c9 80 e1 07 80 c1 30 02 ca 88 18 88 48 01 } //2
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*2) >=5
 
}