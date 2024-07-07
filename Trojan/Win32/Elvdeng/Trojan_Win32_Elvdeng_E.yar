
rule Trojan_Win32_Elvdeng_E{
	meta:
		description = "Trojan:Win32/Elvdeng.E,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {c7 00 64 74 72 52 89 50 08 a3 90 01 04 8d 88 e0 ff 00 00 be fd 07 00 00 eb 03 90 00 } //1
		$a_01_1 = {43 3a 5c 50 72 6f 67 72 61 7e 31 5c 6c 76 65 67 6e 65 64 5c 63 6f 6e 66 69 67 2e 69 6e 69 } //1 C:\Progra~1\lvegned\config.ini
		$a_03_2 = {63 6f 6e 66 69 67 00 90 05 03 01 00 6e 61 76 69 67 61 74 65 75 72 6c 00 90 05 03 01 00 73 69 7a 65 00 90 05 03 01 00 48 4f 4f 4b 42 57 90 00 } //1
		$a_03_3 = {3a 5c 70 6c 75 67 69 6e 90 0f 01 00 2e 90 10 02 00 5c 6c 69 62 5c 72 65 6c 65 61 73 65 5c 64 6c 6c 6f 6e 65 2e 70 64 62 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}