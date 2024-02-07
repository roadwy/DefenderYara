
rule Trojan_Win32_Elvdeng_B{
	meta:
		description = "Trojan:Win32/Elvdeng.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 69 65 64 77 2e 67 68 69 } //01 00  C:\Program Files\iedw.ghi
		$a_01_1 = {43 3a 5c 50 72 6f 67 72 61 7e 31 5c 6c 76 65 67 6e 65 64 5c 63 6f 6e 66 69 67 2e 69 6e 69 } //01 00  C:\Progra~1\lvegned\config.ini
		$a_03_2 = {63 6f 6e 66 69 67 00 90 05 03 01 00 73 74 61 74 69 63 61 6c 75 72 6c 00 90 05 03 01 00 63 68 61 6e 6e 65 6c 00 90 00 } //01 00 
		$a_03_3 = {73 74 61 74 69 63 61 6c 75 72 6c 00 90 05 03 01 00 63 6f 6e 66 69 67 00 90 05 03 01 00 63 68 61 6e 6e 65 6c 00 90 00 } //01 00 
		$a_03_4 = {3a 5c 70 6c 75 67 69 6e 90 0f 01 00 2e 90 10 02 00 5c 72 65 6c 65 61 73 65 5c 65 78 65 74 77 6f 2e 70 64 62 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}