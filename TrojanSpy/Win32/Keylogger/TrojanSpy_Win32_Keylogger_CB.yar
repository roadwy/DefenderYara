
rule TrojanSpy_Win32_Keylogger_CB{
	meta:
		description = "TrojanSpy:Win32/Keylogger.CB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 08 00 00 "
		
	strings :
		$a_01_0 = {53 61 4c 69 4c 6f 47 20 6b 65 79 6c 6f 67 67 65 72 20 73 65 72 76 65 72 } //1 SaLiLoG keylogger server
		$a_01_1 = {5c 00 43 00 72 00 61 00 64 00 65 00 78 00 20 00 53 00 65 00 72 00 76 00 65 00 72 00 5c 00 } //1 \Cradex Server\
		$a_01_2 = {2f 00 76 00 65 00 72 00 69 00 2f 00 73 00 65 00 6e 00 64 00 2e 00 70 00 68 00 70 00 00 00 } //1
		$a_01_3 = {7c 00 20 00 41 00 6c 00 6c 00 20 00 54 00 68 00 65 00 20 00 53 00 74 00 6f 00 72 00 65 00 64 00 20 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 73 00 20 00 26 00 20 00 43 00 6f 00 6d 00 72 00 61 00 64 00 65 00 78 00 2e 00 63 00 6f 00 } //1 | All The Stored Passwords & Comradex.co
		$a_01_4 = {43 00 72 00 61 00 64 00 65 00 78 00 20 00 53 00 74 00 65 00 61 00 6c 00 65 00 72 00 20 00 21 00 20 00 2d 00 20 00 5b 00 } //1 Cradex Stealer ! - [
		$a_01_5 = {42 00 69 00 6c 00 67 00 69 00 73 00 61 00 79 00 61 00 72 00 20 00 41 00 64 00 69 00 20 00 3a 00 20 00 5b 00 } //1 Bilgisayar Adi : [
		$a_01_6 = {4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 69 00 6e 00 67 00 20 00 4b 00 61 00 79 00 64 00 65 00 64 00 69 00 6c 00 6d 00 65 00 20 00 5a 00 61 00 6d 00 61 00 6e 00 } //1 Keylogging Kaydedilme Zaman
		$a_01_7 = {5c 00 46 00 69 00 6c 00 65 00 5a 00 69 00 6c 00 6c 00 61 00 5c 00 00 00 22 00 00 00 72 00 65 00 63 00 65 00 6e 00 74 00 73 00 65 00 72 00 76 00 65 00 72 00 73 00 2e 00 78 00 6d 00 6c 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=5
 
}