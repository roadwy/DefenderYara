
rule TrojanSpy_BAT_Keylogger_HB_bit{
	meta:
		description = "TrojanSpy:BAT/Keylogger.HB!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {77 00 61 00 74 00 63 00 68 00 77 00 69 00 6e 00 73 00 70 00 2e 00 6f 00 72 00 67 00 2f 00 76 00 32 00 2e 00 74 00 78 00 74 00 } //1 watchwinsp.org/v2.txt
		$a_01_1 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_03_2 = {73 00 68 00 75 00 74 00 64 00 6f 00 77 00 6e 00 [0-02] 2f 00 73 00 20 00 2f 00 74 00 20 00 30 00 } //1
		$a_01_3 = {73 65 6e 64 41 63 74 69 76 65 45 6d 61 69 6c } //1 sendActiveEmail
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}