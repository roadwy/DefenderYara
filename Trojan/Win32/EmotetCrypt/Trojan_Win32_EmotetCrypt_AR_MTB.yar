
rule Trojan_Win32_EmotetCrypt_AR_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_81_0 = {43 3a 5c 55 73 65 72 73 5c 44 4f 44 4f 5c 56 69 64 65 6f 73 5c 77 69 6e 33 32 5f 6d 65 6d 64 63 5f 73 72 63 5c 52 65 6c 65 61 73 65 5c 57 69 6e 33 32 5f 4d 65 6d 44 43 2e 70 64 62 } //01 00  C:\Users\DODO\Videos\win32_memdc_src\Release\Win32_MemDC.pdb
		$a_81_1 = {43 53 42 68 76 53 57 43 76 46 52 76 66 43 66 41 6f 4a 64 6f 46 75 41 55 6d 4b } //00 00  CSBhvSWCvFRvfCfAoJdoFuAUmK
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_EmotetCrypt_AR_MTB_2{
	meta:
		description = "Trojan:Win32/EmotetCrypt.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 14 2b 8a 03 03 54 24 10 0f b6 c0 03 c2 33 d2 f7 f1 8a 03 47 43 8a 0c 32 88 04 32 88 4b ff 8b 0d 90 01 04 3b f9 89 54 24 10 90 00 } //01 00 
		$a_01_1 = {8b 44 24 10 8b 4c 24 18 8a 14 01 8b 4c 24 1c 32 14 31 40 88 50 ff 89 44 24 10 ff 4c 24 14 } //01 00 
		$a_81_2 = {4c 39 67 66 65 66 64 54 54 52 76 68 } //00 00  L9gfefdTTRvh
		$a_00_3 = {78 } //8c 00  x
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_EmotetCrypt_AR_MTB_3{
	meta:
		description = "Trojan:Win32/EmotetCrypt.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 44 24 14 8d 2c 3b 88 1c 28 8b c3 99 f7 7c 24 2c 8b 44 24 28 43 3b de 8a 14 02 88 55 00 } //01 00 
		$a_01_1 = {33 d2 f7 f6 8a 03 43 8b fa 8a 14 0f 88 04 0f 8b 44 24 14 88 53 ff 48 89 7c 24 10 89 44 24 14 } //02 00 
		$a_01_2 = {88 14 0f 88 04 29 0f b6 14 29 0f b6 04 0f 03 c2 33 d2 f7 f6 8a 04 0a 8b 54 24 18 32 04 1a 43 88 43 ff ff 4c 24 14 } //01 00 
		$a_81_3 = {42 35 36 77 72 67 37 51 72 78 74 74 68 } //00 00  B56wrg7Qrxtth
		$a_00_4 = {78 94 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_EmotetCrypt_AR_MTB_4{
	meta:
		description = "Trojan:Win32/EmotetCrypt.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c3 99 f7 7c 24 2c 8b 44 24 28 8d 0c 2b 88 1c 0e 43 8a 14 02 88 11 8b 0d 90 01 04 3b d9 72 90 00 } //01 00 
		$a_03_1 = {0f b6 14 2e 8a 06 03 54 24 10 0f b6 c0 03 c2 33 d2 f7 f1 8a 06 43 46 8a 0c 3a 88 04 3a 88 4e ff 8b 0d 90 01 04 3b d9 89 54 24 10 72 90 00 } //01 00 
		$a_01_2 = {8b 44 24 24 8b 4c 24 14 8a 14 01 8b 4c 24 18 32 14 39 40 88 50 ff 89 44 24 24 ff 4c 24 10 75 } //03 00 
		$a_81_3 = {51 79 69 6e 79 68 6a 6a 62 74 36 37 } //00 00  Qyinyhjjbt67
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_EmotetCrypt_AR_MTB_5{
	meta:
		description = "Trojan:Win32/EmotetCrypt.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {8a 54 24 20 88 14 0f 88 04 0e 0f b6 14 0e 0f b6 04 0f 03 c2 33 d2 f7 35 90 01 04 8a 04 0a 8b 54 24 14 32 04 1a 43 88 43 ff ff 4c 24 10 90 00 } //01 00 
		$a_81_1 = {79 36 69 74 68 67 72 68 68 79 74 74 } //01 00  y6ithgrhhytt
		$a_81_2 = {63 3a 5c 55 73 65 72 73 5c 44 6f 64 6f 5c 44 6f 77 6e 6c 6f 61 64 73 5c 57 65 62 50 61 67 65 53 6e 61 70 53 68 6f 74 5c 52 65 6c 65 61 73 65 5c 57 65 62 50 61 67 65 53 6e 61 70 53 68 6f 74 2e 70 64 62 } //00 00  c:\Users\Dodo\Downloads\WebPageSnapShot\Release\WebPageSnapShot.pdb
		$a_00_3 = {78 9d } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_EmotetCrypt_AR_MTB_6{
	meta:
		description = "Trojan:Win32/EmotetCrypt.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 44 24 14 8d 34 3b 88 1c 30 8b c3 99 f7 7c 24 2c 8b 44 24 28 43 8a 14 02 88 16 8b 2d 90 01 04 3b dd 90 00 } //01 00 
		$a_01_1 = {0f b6 14 1f 03 54 24 10 8a 03 0f b6 c0 03 c2 33 d2 f7 f5 8a 03 46 43 8b ea 8a 14 29 88 04 29 88 53 ff 89 6c 24 10 } //01 00 
		$a_01_2 = {03 54 24 14 8a 04 0a 8b 54 24 18 02 c3 32 04 2a 45 88 45 ff 8b 44 24 10 48 89 6c 24 24 89 44 24 10 } //01 00 
		$a_81_3 = {64 72 74 66 66 44 57 45 55 46 45 55 46 55 57 45 47 46 55 59 42 47 } //00 00  drtffDWEUFEUFUWEGFUYBG
		$a_00_4 = {7e } //15 00  ~
	condition:
		any of ($a_*)
 
}