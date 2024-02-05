
rule TrojanSpy_BAT_Keylogger_BJ{
	meta:
		description = "TrojanSpy:BAT/Keylogger.BJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_80_0 = {72 61 6c 70 68 79 78 39 38 37 36 40 67 6d 61 69 6c 2e 63 6f 6d } //ralphyx9876@gmail.com  01 00 
		$a_80_1 = {79 32 75 7a 6b 63 72 71 7a 74 6e 38 78 6e 77 } //y2uzkcrqztn8xnw  01 00 
		$a_80_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //SOFTWARE\Microsoft\Windows\CurrentVersion\Run  00 00 
	condition:
		any of ($a_*)
 
}