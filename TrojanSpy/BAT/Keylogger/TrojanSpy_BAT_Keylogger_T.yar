
rule TrojanSpy_BAT_Keylogger_T{
	meta:
		description = "TrojanSpy:BAT/Keylogger.T,SIGNATURE_TYPE_PEHSTR,04 00 02 00 05 00 00 "
		
	strings :
		$a_01_0 = {7b 00 30 00 7d 00 7b 00 31 00 7d 00 7b 00 32 00 7d 00 7b 00 33 00 7d 00 7b 00 34 00 7d 00 7b 00 35 00 7d 00 7b 00 36 00 7d 00 2e 00 65 00 78 00 65 00 } //1 {0}{1}{2}{3}{4}{5}{6}.exe
		$a_01_1 = {74 00 61 00 6b 00 65 00 6e 00 20 00 6f 00 6e 00 20 00 7b 00 34 00 7d 00 20 00 61 00 74 00 20 00 7b 00 35 00 7d 00 3a 00 7b 00 36 00 7d 00 3a 00 7b 00 37 00 7d 00 } //1 taken on {4} at {5}:{6}:{7}
		$a_01_2 = {73 00 6d 00 74 00 70 00 2e 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00 } //1 smtp.gmail.com
		$a_01_3 = {57 00 69 00 6e 00 64 00 6f 00 77 00 20 00 54 00 69 00 74 00 6c 00 65 00 3a 00 20 00 7b 00 32 00 7d 00 0d 00 0a 00 54 00 69 00 6d 00 65 00 3a 00 20 00 7b 00 33 00 7d 00 3a 00 7b 00 34 00 7d 00 3a 00 7b 00 35 00 7d 00 } //1
		$a_01_4 = {7b 00 30 00 7d 00 7b 00 31 00 7d 00 7b 00 32 00 7d 00 7b 00 33 00 7d 00 2e 00 6a 00 70 00 67 00 } //1 {0}{1}{2}{3}.jpg
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=2
 
}