
rule Ransom_Win32_Cerber_A_{
	meta:
		description = "Ransom:Win32/Cerber.A!!Cerber.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,08 00 08 00 05 00 00 05 00 "
		
	strings :
		$a_00_0 = {63 65 72 62 65 72 00 } //01 00 
		$a_00_1 = {63 72 79 70 74 69 6d 70 6f 72 74 70 75 62 6c 69 63 6b 65 79 69 6e 66 6f } //01 00 
		$a_00_2 = {63 72 79 70 74 65 6e 63 72 79 70 74 } //02 00 
		$a_01_3 = {0f b6 f0 83 fe 66 7f 30 74 25 83 fe 26 74 17 83 fe 2e 74 12 83 fe 36 74 0d 83 fe 3e 74 08 83 c6 9c 83 fe 01 } //02 00 
		$a_00_4 = {c1 e8 10 33 c2 69 c0 6b ca eb 85 8b c8 c1 e9 0d 33 c8 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_Cerber_A__2{
	meta:
		description = "Ransom:Win32/Cerber.A!!Cerber.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,06 00 06 00 07 00 00 02 00 "
		
	strings :
		$a_80_0 = {4b 65 79 73 69 7a 65 3a 20 25 64 2c 20 45 6e 63 72 79 70 74 69 6f 6e 20 74 69 6d 65 3a 20 25 64 } //Keysize: %d, Encryption time: %d  02 00 
		$a_80_1 = {54 6f 74 61 6c 20 66 69 6c 65 73 20 66 6f 75 6e 64 3a 20 25 64 2c 20 46 69 6c 65 73 20 63 72 79 70 74 65 64 3a 20 25 64 } //Total files found: %d, Files crypted: %d  02 00 
		$a_80_2 = {7b 22 76 65 6e 64 6f 72 73 22 3a 5b 22 56 69 72 75 73 42 6c 6f 6b 41 64 61 22 2c 22 4d 61 6c 77 61 72 65 62 79 74 65 73 22 5d 7d } //{"vendors":["VirusBlokAda","Malwarebytes"]}  01 00 
		$a_00_3 = {63 65 72 62 65 72 00 } //02 00 
		$a_01_4 = {c7 06 63 72 62 72 } //01 00 
		$a_03_5 = {ff 75 08 c6 45 90 01 01 b8 66 c7 45 90 01 01 50 b8 89 90 01 01 e3 66 c7 45 90 01 01 ff d0 c6 45 90 01 01 c3 ff d6 90 00 } //02 00 
		$a_01_6 = {8b 4c 24 04 c7 00 6e 6f 73 6a 89 48 14 c3 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_Cerber_A__3{
	meta:
		description = "Ransom:Win32/Cerber.A!!Cerber.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 0a 00 00 01 00 "
		
	strings :
		$a_80_0 = {45 6e 63 72 79 70 74 69 6e 67 20 64 6f 6e 65 2e 20 54 69 6d 65 20 6c 65 66 74 3a 20 25 64 6d 73 } //Encrypting done. Time left: %dms  01 00 
		$a_80_1 = {4e 65 74 77 6f 72 6b 20 73 65 61 72 63 68 69 6e 67 20 64 6f 6e 65 2e 20 54 69 6d 65 20 6c 65 66 74 3a 20 25 64 6d 73 } //Network searching done. Time left: %dms  01 00 
		$a_80_2 = {43 72 79 70 74 49 6d 70 6f 72 74 4b 65 79 20 66 61 69 6c 65 64 2c 20 47 65 74 4c 61 73 74 45 72 72 6f 72 20 3d 3d 20 25 78 } //CryptImportKey failed, GetLastError == %x  02 00 
		$a_01_3 = {c7 03 44 72 62 52 66 89 43 15 } //01 00 
		$a_01_4 = {b8 42 4d 00 00 53 66 89 45 a0 } //01 00 
		$a_01_5 = {c7 45 d8 08 02 00 00 c7 45 dc 01 68 00 00 89 75 e0 } //01 00 
		$a_01_6 = {c7 06 06 02 00 00 c7 46 04 00 a4 00 00 c7 46 08 52 53 41 31 } //01 00 
		$a_01_7 = {b8 ba ba ba ab 39 46 04 75 11 } //01 00 
		$a_01_8 = {f6 45 08 08 b9 ba ba ba ab 89 30 89 48 04 89 4c 30 08 } //01 00 
		$a_01_9 = {8d 46 f8 8b 10 50 b9 ef be ad de } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_Cerber_A__4{
	meta:
		description = "Ransom:Win32/Cerber.A!!Cerber.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 14 00 00 01 00 "
		
	strings :
		$a_80_0 = {4d 53 43 54 46 2e 53 68 61 72 65 64 2e 4d 55 54 45 58 2e 25 30 38 78 } //MSCTF.Shared.MUTEX.%08x  02 00 
		$a_80_1 = {43 45 52 42 45 52 5f 4b 45 59 5f 50 4c 41 43 45 } //CERBER_KEY_PLACE  02 00 
		$a_80_2 = {7b 25 30 38 58 2d 25 30 34 58 2d 25 30 34 58 2d 25 30 32 58 25 30 32 58 2d 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 7d } //{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}  01 00 
		$a_80_3 = {50 72 69 6e 74 65 72 73 5c 44 65 66 61 75 6c 74 73 5c 25 73 } //Printers\Defaults\%s  01 00 
		$a_80_4 = {43 6f 6d 70 6f 6e 65 6e 74 5f 30 30 } //Component_00  03 00 
		$a_80_5 = {7b 4d 44 35 5f 4b 45 59 7d 7b 50 41 52 54 4e 45 52 5f 49 44 7d 7b 4f 53 7d 7b 49 53 5f 58 36 34 7d 7b 49 53 5f 41 44 4d 49 4e 7d 7b 43 4f 55 4e 54 5f 46 49 4c 45 53 7d 7b 53 54 4f 50 5f 52 45 41 53 4f 4e 7d } //{MD5_KEY}{PARTNER_ID}{OS}{IS_X64}{IS_ADMIN}{COUNT_FILES}{STOP_REASON}  01 00 
		$a_80_6 = {2f 7b 50 43 5f 49 44 7d } ///{PC_ID}  02 00 
		$a_80_7 = {53 41 50 49 2e 53 70 65 61 6b 20 5c 22 59 6f 75 72 20 64 6f 63 75 6d 65 6e 74 73 2c 20 70 68 6f 74 6f 73 2c 20 64 61 74 61 62 61 73 65 73 20 61 6e 64 20 6f 74 68 65 72 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 21 5c 22 } //SAPI.Speak \"Your documents, photos, databases and other important files have been encrypted!\"  02 00 
		$a_80_8 = {22 66 69 6c 65 5f 65 78 74 65 6e 73 69 6f 6e 22 3a 22 2e 76 62 73 22 7d 5d 2c 22 66 69 6c 65 73 5f 6e 61 6d 65 22 3a } //"file_extension":".vbs"}],"files_name":  02 00 
		$a_80_9 = {22 73 65 72 76 65 72 73 22 3a 7b 22 73 74 61 74 69 73 74 69 63 73 22 3a 7b 22 64 61 74 61 5f 66 69 6e 69 73 68 22 3a 22 7b 4d 44 35 5f 4b 45 59 7d 22 } //"servers":{"statistics":{"data_finish":"{MD5_KEY}"  01 00 
		$a_80_10 = {22 23 20 44 45 43 52 59 50 54 20 4d 59 20 46 49 4c 45 53 20 23 22 } //"# DECRYPT MY FILES #"  01 00 
		$a_80_11 = {69 70 69 6e 66 6f 2e 69 6f 2f 6a 73 6f 6e } //ipinfo.io/json  01 00 
		$a_80_12 = {66 72 65 65 67 65 6f 69 70 2e 6e 65 74 2f 6a 73 6f 6e } //freegeoip.net/json  01 00 
		$a_80_13 = {69 70 2d 61 70 69 2e 63 6f 6d 2f 6a 73 6f 6e } //ip-api.com/json  02 00 
		$a_03_14 = {c7 03 44 72 62 52 66 89 43 0f ff 15 90 01 04 8d 44 00 02 66 89 43 06 90 00 } //02 00 
		$a_00_15 = {c1 e8 10 33 c2 69 c0 6b ca eb 85 8b c8 c1 e9 0d 33 c8 } //01 00 
		$a_80_16 = {43 45 52 42 45 52 5f 45 56 41 4c 55 41 54 45 44 5f 43 4f 52 45 5f 50 52 4f 54 45 43 54 49 4f 4e 5f 45 56 45 4e 54 } //CERBER_EVALUATED_CORE_PROTECTION_EVENT  01 00 
		$a_80_17 = {22 73 71 6c 77 72 69 74 65 72 2e 65 78 65 22 2c 22 6f 72 61 63 6c 65 2e 65 78 65 22 2c 22 6f 63 73 73 64 2e 65 78 65 22 2c 22 64 62 73 6e 6d 70 2e 65 78 65 22 2c 22 73 79 6e 63 74 69 6d 65 2e 65 78 65 22 } //"sqlwriter.exe","oracle.exe","ocssd.exe","dbsnmp.exe","synctime.exe"  01 00 
		$a_80_18 = {63 65 72 62 65 72 5f 64 65 62 75 67 2e 74 78 74 } //cerber_debug.txt  01 00 
		$a_80_19 = {43 45 52 42 45 52 5f 43 4f 52 45 5f 50 52 4f 54 45 43 54 49 4f 4e 5f 4d 55 54 45 58 } //CERBER_CORE_PROTECTION_MUTEX  00 00 
	condition:
		any of ($a_*)
 
}