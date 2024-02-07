
rule Trojan_Win32_Snow_A{
	meta:
		description = "Trojan:Win32/Snow.A,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 20 00 41 00 6c 00 6c 00 20 00 72 00 69 00 67 00 68 00 74 00 73 00 20 00 72 00 65 00 73 00 65 00 72 00 76 00 65 00 64 00 2e 00 } //01 00  Microsoft Corporation. All rights reserved.
		$a_01_1 = {66 6f 72 6d 61 74 20 5a 3a 2f 78 2f 71 20 2f 59 } //01 00  format Z:/x/q /Y
		$a_01_2 = {5c 5c 2e 5c 5a 3a } //01 00  \\.\Z:
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 53 4e 4f 57 } //01 00  SOFTWARE\SNOW
		$a_01_4 = {28 65 74 68 65 72 20 64 73 74 20 46 46 3a 46 46 3a 46 46 3a 46 46 3a 46 46 3a 46 46 29 20 26 26 20 75 64 70 20 26 26 20 28 68 6f 73 74 20 30 2e 30 2e 30 2e 30 29 } //01 00  (ether dst FF:FF:FF:FF:FF:FF) && udp && (host 0.0.0.0)
		$a_01_5 = {44 3a 5c 64 65 6c 2e 74 78 74 } //01 00  D:\del.txt
		$a_01_6 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_7 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 41 63 74 69 76 65 53 74 61 74 65 20 50 65 72 6c 20 44 65 76 20 4b 69 74 20 36 2e 30 5c 62 69 6e 5c 70 64 6b 64 65 62 75 67 2e 65 78 65 } //00 00  C:\Program Files\ActiveState Perl Dev Kit 6.0\bin\pdkdebug.exe
	condition:
		any of ($a_*)
 
}