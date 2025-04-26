
rule TrojanSpy_BAT_Keylogger_AS{
	meta:
		description = "TrojanSpy:BAT/Keylogger.AS,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6e 37 61 4b 65 79 6c 6f 67 67 65 72 } //1 n7aKeylogger
		$a_01_1 = {4b 4c 47 5f 50 6f 6c 6c 69 6e 67 } //1 KLG_Polling
		$a_01_2 = {2f 00 77 00 69 00 6e 00 64 00 6f 00 77 00 2e 00 70 00 6e 00 67 00 } //1 /window.png
		$a_01_3 = {69 00 3d 00 4d 00 73 00 54 00 72 00 6f 00 } //1 i=MsTro
		$a_01_4 = {73 00 6d 00 74 00 70 00 2e 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00 } //1 smtp.gmail.com
		$a_01_5 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}