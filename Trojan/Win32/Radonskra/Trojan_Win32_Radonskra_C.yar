
rule Trojan_Win32_Radonskra_C{
	meta:
		description = "Trojan:Win32/Radonskra.C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 77 69 6e 64 6f 77 73 2e 7a 70 78 } //01 00  \Microsoft\Windows\windows.zpx
		$a_01_1 = {22 73 61 66 65 62 72 6f 77 73 69 6e 67 22 3a 7b 22 65 6e 61 62 6c 65 64 22 3a 66 61 6c 73 65 7d } //01 00  "safebrowsing":{"enabled":false}
		$a_01_2 = {22 68 6f 6d 65 70 61 67 65 55 52 4c 22 3a 22 68 74 74 70 3a 2f 2f 77 77 77 2e 67 72 65 61 73 65 73 70 6f 74 2e 6e 65 74 2f 22 } //01 00  "homepageURL":"http://www.greasespot.net/"
		$a_01_3 = {2f 63 72 65 61 74 65 20 2f 74 6e 20 53 79 73 74 65 6d 53 63 72 69 70 74 20 2f 74 72 20 22 44 57 56 41 4c 55 45 22 20 2f 73 63 20 4f 4e 4c 4f 47 4f 4e 20 2f 66 } //01 00  /create /tn SystemScript /tr "DWVALUE" /sc ONLOGON /f
		$a_01_4 = {4c 79 38 67 50 54 31 56 63 32 56 79 55 32 4e 79 61 58 42 30 50 54 30 4e 43 69 38 76 49 45 42 70 62 6d 4e 73 64 57 52 6c 49 47 68 30 64 48 41 36 4c 79 38 71 44 51 6f 76 4c 79 42 41 61 57 35 6a 62 48 56 6b 5a 53 42 6f 64 48 52 77 63 7a 6f 76 4c 79 6f 4e 43 69 38 76 49 44 30 39 4c 31 56 7a 5a 58 4a 54 59 33 4a 70 63 48 51 39 50 51 30 4b 44 51 } //00 00  Ly8gPT1Vc2VyU2NyaXB0PT0NCi8vIEBpbmNsdWRlIGh0dHA6Ly8qDQovLyBAaW5jbHVkZSBodHRwczovLyoNCi8vID09L1VzZXJTY3JpcHQ9PQ0KDQ
		$a_00_5 = {5d 04 00 } //00 4b 
	condition:
		any of ($a_*)
 
}