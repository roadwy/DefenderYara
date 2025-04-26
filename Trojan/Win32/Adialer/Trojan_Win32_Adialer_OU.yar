
rule Trojan_Win32_Adialer_OU{
	meta:
		description = "Trojan:Win32/Adialer.OU,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 19 00 08 00 00 "
		
	strings :
		$a_02_0 = {7e 21 70 61 73 73 77 6f 72 64 [0-02] 21 7e 21 [0-20] 40 6f 63 65 61 6e } //10
		$a_02_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 61 72 65 61 78 78 78 2e 62 69 7a 2f [0-10] 2e 70 68 70 } //10
		$a_00_2 = {2e 6c 6e 6b } //1 .lnk
		$a_00_3 = {45 52 52 4f 52 5f 43 41 4e 4e 4f 54 5f 4f 50 45 4e 5f 50 48 4f 4e 45 42 4f 4f 4b } //1 ERROR_CANNOT_OPEN_PHONEBOOK
		$a_00_4 = {52 61 73 44 69 61 6c 41 } //1 RasDialA
		$a_00_5 = {58 58 58 43 6c 61 73 73 } //1 XXXClass
		$a_00_6 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 } //1 Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
		$a_00_7 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //1 shell\open\command
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=25
 
}