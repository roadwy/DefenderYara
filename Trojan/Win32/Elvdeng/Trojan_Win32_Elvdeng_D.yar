
rule Trojan_Win32_Elvdeng_D{
	meta:
		description = "Trojan:Win32/Elvdeng.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {68 ff 0f 1f 00 ff 15 ?? ?? ?? ?? 8b f0 85 f6 74 ?? 8b 44 24 ?? 6a 04 68 00 10 00 00 83 c0 01 50 6a 00 56 ff 15 } //1
		$a_01_1 = {43 3a 5c 50 72 6f 67 72 61 7e 31 5c 6c 76 65 67 6e 65 64 5c 63 6f 6e 66 69 67 2e 69 6e 69 } //1 C:\Progra~1\lvegned\config.ini
		$a_03_2 = {63 6f 6e 66 69 67 00 90 05 03 01 00 6e 61 76 69 67 61 74 65 75 72 6c 00 90 05 03 01 00 69 6e 73 74 61 6c 6c 00 90 05 03 01 00 44 49 52 45 43 54 4f 52 59 } //1
		$a_03_3 = {3a 5c 70 6c 75 67 69 6e 90 0f 01 00 2e 90 10 02 00 5c 72 65 6c 65 61 73 65 5c 65 78 65 6f 6e 65 2e 70 64 62 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}