
rule Trojan_Win32_ExtenBro_A{
	meta:
		description = "Trojan:Win32/ExtenBro.A,SIGNATURE_TYPE_PEHSTR_EXT,22 00 22 00 09 00 00 0a 00 "
		
	strings :
		$a_03_0 = {3c 6e 61 6d 65 3e 51 75 69 63 6b 20 53 65 61 72 63 68 65 72 90 02 04 3c 2f 6e 61 6d 65 3e 90 00 } //0a 00 
		$a_03_1 = {3c 65 6d 3a 64 65 73 63 72 69 70 74 69 6f 6e 3e 51 75 69 63 6b 20 53 65 61 72 63 68 65 72 90 02 04 3c 2f 65 6d 3a 64 65 73 63 72 69 70 74 69 6f 6e 3e 90 00 } //0a 00 
		$a_01_2 = {31 32 37 2e 30 2e 30 2e 31 20 63 6c 69 65 6e 74 73 32 2e 67 6f 6f 67 6c 65 2e 63 6f 6d } //0a 00  127.0.0.1 clients2.google.com
		$a_01_3 = {5c 73 69 67 6e 61 6c 2e 64 61 74 } //01 00  \signal.dat
		$a_01_4 = {5c 59 61 6e 64 65 78 5c 59 61 6e 64 65 78 42 72 6f 77 73 65 72 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c } //01 00  \Yandex\YandexBrowser\User Data\Default\
		$a_01_5 = {5c 41 6d 69 67 6f 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 45 78 74 65 6e 73 69 6f 6e 20 44 61 74 61 } //01 00  \Amigo\User Data\Default\Extension Data
		$a_01_6 = {5c 4f 70 65 72 61 20 53 6f 66 74 77 61 72 65 5c 4f 70 65 72 61 20 53 74 61 62 6c 65 5c 50 72 65 66 65 72 65 6e 63 65 73 } //01 00  \Opera Software\Opera Stable\Preferences
		$a_00_7 = {41 76 61 73 74 53 76 63 2e 65 78 65 } //01 00  AvastSvc.exe
		$a_00_8 = {61 76 67 72 73 78 2e 65 78 65 } //00 00  avgrsx.exe
		$a_00_9 = {80 10 00 00 af e5 75 21 dc e8 f3 9d 69 07 8c d5 00 10 00 80 80 10 00 00 } //4a 66 
	condition:
		any of ($a_*)
 
}