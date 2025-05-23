
rule TrojanSpy_Win32_Bholog_B{
	meta:
		description = "TrojanSpy:Win32/Bholog.B,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 0a 00 00 "
		
	strings :
		$a_03_0 = {6f 73 73 6b [0-0c] 66 72 6d 4c 6f 67 69 6e } //2
		$a_01_1 = {5b 00 41 00 4c 00 54 00 55 00 50 00 5d 00 } //2 [ALTUP]
		$a_00_2 = {5b 00 50 00 41 00 53 00 54 00 45 00 5d 00 } //2 [PASTE]
		$a_01_3 = {72 65 61 64 69 6e 67 00 72 65 70 62 68 61 69 } //1
		$a_01_4 = {69 6b 6b 00 72 61 73 74 61 62 72 6f 00 } //1
		$a_01_5 = {53 00 65 00 6c 00 65 00 63 00 74 00 20 00 2a 00 20 00 66 00 72 00 6f 00 6d 00 20 00 44 00 61 00 74 00 41 00 63 00 63 00 6f 00 75 00 6e 00 74 00 73 00 00 00 } //1
		$a_01_6 = {64 69 6b 68 61 78 00 00 44 61 74 41 63 63 65 73 73 00 } //1
		$a_01_7 = {3a 00 5c 00 64 00 65 00 6b 00 68 00 74 00 65 00 5f 00 68 00 65 00 69 00 6e 00 5c 00 64 00 65 00 65 00 2e 00 76 00 62 00 70 00 00 00 } //1
		$a_01_8 = {61 6c 74 61 66 5f 62 68 61 69 00 } //1
		$a_01_9 = {4c 6f 67 69 6e 53 75 63 63 65 65 64 65 64 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_00_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=7
 
}
rule TrojanSpy_Win32_Bholog_B_2{
	meta:
		description = "TrojanSpy:Win32/Bholog.B,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_01_0 = {4d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 73 00 20 00 61 00 6e 00 64 00 20 00 72 00 65 00 63 00 6f 00 72 00 64 00 73 00 20 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 } //1 Monitors and records Internet connection.
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 74 00 68 00 6f 00 6e 00 67 00 6b 00 6f 00 72 00 6e 00 2e 00 63 00 6f 00 6d 00 2f 00 4d 00 79 00 49 00 50 00 2e 00 70 00 68 00 70 00 } //1 http://www.thongkorn.com/MyIP.php
		$a_01_2 = {00 00 5c 00 4c 00 6f 00 67 00 67 00 69 00 6e 00 67 00 2e 00 74 00 78 00 74 00 00 00 } //1
		$a_01_3 = {53 00 65 00 6c 00 65 00 63 00 74 00 20 00 2a 00 20 00 66 00 72 00 6f 00 6d 00 20 00 44 00 61 00 74 00 41 00 63 00 63 00 6f 00 75 00 6e 00 74 00 73 00 } //1 Select * from DatAccounts
		$a_01_4 = {66 72 6d 4d 6f 6e 69 74 6f 72 49 6e 74 65 72 6e 65 74 } //1 frmMonitorInternet
		$a_01_5 = {5c 00 64 00 65 00 6b 00 68 00 74 00 65 00 73 00 64 00 5f 00 68 00 65 00 69 00 6e 00 73 00 64 00 5c 00 66 00 64 00 66 00 64 00 66 00 2e 00 76 00 62 00 70 00 } //2 \dekhtesd_heinsd\fdfdf.vbp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*2) >=7
 
}