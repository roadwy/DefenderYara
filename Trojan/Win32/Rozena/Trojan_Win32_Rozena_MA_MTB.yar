
rule Trojan_Win32_Rozena_MA_MTB{
	meta:
		description = "Trojan:Win32/Rozena.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 0c 8b 4d f0 8b 55 f0 88 14 08 8b 45 f0 89 45 ec ff 45 f0 eb } //01 00 
		$a_03_1 = {0f be 0c 11 31 c8 90 0a 12 00 8b 45 90 01 01 8b 4d 0c 8b 55 90 02 09 8b 4d 10 8b 55 90 01 01 88 04 11 8b 45 90 01 01 89 45 90 01 01 ff 45 90 01 01 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Rozena_MA_MTB_2{
	meta:
		description = "Trojan:Win32/Rozena.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {66 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 4c 4a 44 45 4c 4a 44 4d 4c 4b 41 5a 44 4a 44 4c 4b 4a 5a 45 4c 4b } //02 00 
		$a_01_1 = {43 6f 72 6b 69 65 73 74 20 66 65 61 74 75 72 65 66 75 6c 20 64 75 63 74 69 6c 65 6e 65 73 73 } //02 00 
		$a_01_2 = {72 74 62 45 77 36 48 49 78 70 50 4a 2b 55 30 63 76 57 58 6b 75 55 45 73 78 52 75 71 53 53 39 4f } //02 00 
		$a_01_3 = {3c 00 3c 00 48 00 54 00 54 00 50 00 5f 00 46 00 49 00 4c 00 45 00 4e 00 41 00 4d 00 45 00 5f 00 50 00 41 00 59 00 4c 00 4f 00 41 00 44 00 3e 00 3e 00 } //00 00 
	condition:
		any of ($a_*)
 
}