rule Backdoor_Win32_Aconti{
	meta:
		description = "Backdoor:Win32/Aconti,SIGNATURE_TYPE_PEHSTR,08 00 08 00 0b 00 00 "
		
	strings :
		$a_01_0 = {61 00 63 00 6f 00 6e 00 74 00 69 00 20 00 4e 00 65 00 74 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 } //1 aconti NetService
		$a_01_1 = {70 6f 72 74 2e 61 63 6f 6e 74 69 2e 6e 65 74 2f 64 69 61 6c 65 72 } //1 port.aconti.net/dialer
		$a_01_2 = {41 4c 69 66 65 73 74 79 6c 65 2e 61 63 6f 6e 74 69 } //1 ALifestyle.aconti
		$a_01_3 = {41 4c 69 66 65 44 69 61 6c 65 72 } //1 ALifeDialer
		$a_01_4 = {53 65 63 75 72 65 44 69 61 6c 65 72 } //1 SecureDialer
		$a_01_5 = {67 6f 6f 64 74 68 69 6e 78 78 } //1 goodthinxx
		$a_01_6 = {64 69 61 6c 65 72 2f 73 74 75 62 2e 65 78 65 } //1 dialer/stub.exe
		$a_01_7 = {64 69 61 6c 65 72 68 61 73 68 77 65 72 74 3d 25 73 26 64 69 61 6c 65 72 76 65 72 73 69 6f 6e 3d 25 75 25 73 25 73 } //1 dialerhashwert=%s&dialerversion=%u%s%s
		$a_01_8 = {53 6f 66 74 77 61 72 65 5c 41 4c 69 66 65 73 74 79 6c 65 5c } //1 Software\ALifestyle\
		$a_01_9 = {53 68 6f 77 45 72 6f 74 69 63 } //1 ShowErotic
		$a_01_10 = {25 73 3f 55 49 44 3d 25 75 26 4e 72 3d 25 73 26 43 6f 75 6e 74 72 79 3d 25 73 26 69 6e 64 63 6f 64 65 3d 25 75 } //1 %s?UID=%u&Nr=%s&Country=%s&indcode=%u
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=8
 
}