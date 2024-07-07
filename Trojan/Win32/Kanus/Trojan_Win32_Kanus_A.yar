
rule Trojan_Win32_Kanus_A{
	meta:
		description = "Trojan:Win32/Kanus.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 54 45 4d 50 5c 5c 7e 78 2e 62 61 74 } //1 C:\TEMP\\~x.bat
		$a_01_1 = {69 66 20 65 78 69 73 74 20 43 3a 5c 6d 79 61 70 70 2e 65 78 65 20 67 6f 74 6f 20 74 72 79 } //1 if exist C:\myapp.exe goto try
		$a_01_2 = {43 3a 5c 54 45 4d 50 5c 5c 6b 65 72 6e 65 6c 2e 65 78 65 } //1 C:\TEMP\\kernel.exe
		$a_01_3 = {33 4d 00 33 c0 8a c1 89 4c 24 10 33 db 83 ed 04 25 ff 00 00 00 8b d0 8b c1 c1 e8 08 8a d8 c1 e8 08 8b c8 c1 e9 08 81 e1 ff 00 00 00 8b 4c 8e 48 25 ff 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}