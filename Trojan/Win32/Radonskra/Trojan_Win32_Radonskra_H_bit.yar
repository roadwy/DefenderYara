
rule Trojan_Win32_Radonskra_H_bit{
	meta:
		description = "Trojan:Win32/Radonskra.H!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_1 = {4c 79 38 67 50 54 31 56 63 32 56 79 55 32 4e 79 61 58 42 30 50 54 30 4e 43 69 38 76 49 45 42 70 62 6d 4e 73 64 57 52 6c 49 47 68 30 64 48 41 36 4c 79 38 71 44 51 6f 76 4c 79 42 41 61 57 35 6a 62 48 56 6b 5a 53 42 6f 64 48 52 77 63 7a 6f 76 4c 79 6f 4e 43 69 38 76 49 44 30 39 4c 31 56 7a 5a 58 4a 54 59 33 4a 70 63 48 51 39 50 51 30 4b 44 51 } //1 Ly8gPT1Vc2VyU2NyaXB0PT0NCi8vIEBpbmNsdWRlIGh0dHA6Ly8qDQovLyBAaW5jbHVkZSBodHRwczovLyoNCi8vID09L1VzZXJTY3JpcHQ9PQ0KDQ
		$a_01_2 = {22 73 61 66 65 62 72 6f 77 73 69 6e 67 22 3a 7b 22 65 6e 61 62 6c 65 64 22 3a 66 61 6c 73 65 7d } //1 "safebrowsing":{"enabled":false}
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 56 61 6c 75 65 4f 66 57 69 6e 64 6f 77 } //1 Software\Microsoft\Windows\ValueOfWindow
		$a_01_4 = {2e 70 68 70 3f 73 6e 69 64 3d } //1 .php?snid=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}