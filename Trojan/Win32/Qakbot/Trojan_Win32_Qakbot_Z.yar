
rule Trojan_Win32_Qakbot_Z{
	meta:
		description = "Trojan:Win32/Qakbot.Z,SIGNATURE_TYPE_PEHSTR_EXT,ffffffc9 00 ffffffc9 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //64 00 
		$a_01_1 = {c7 45 10 5a 00 00 00 33 d2 8b c6 f7 75 10 8a 04 0a 8b 55 fc 3a 04 16 74 11 46 3b f3 72 e9 } //64 00 
		$a_01_2 = {33 d2 8b c7 f7 75 10 8a 04 0a 8b 55 fc 32 04 17 88 04 3b 47 83 ee 01 75 e7 8b 4d f8 eb b6 } //00 00 
		$a_00_3 = {5d 04 00 00 98 bd 04 80 5c 3a 00 00 9a bd 04 80 00 00 01 00 25 00 24 00 54 72 6f 6a 61 6e 44 72 6f 70 70 65 72 3a 41 6e 64 72 6f 69 64 4f 53 2f 42 61 6e 6b 65 72 2e 50 21 4d 54 42 00 00 02 40 05 82 5d 00 04 00 67 16 00 00 55 8f 67 c6 c7 9b 73 ab 96 a5 33 46 3b 0c 4b 00 01 20 1b 4c 72 ec 8c fe 00 00 05 00 05 00 04 00 00 02 00 7a 03 48 83 ec 38 48 89 d5 48 89 fb 48 8b 07 48 8d 35 90 01 02 ff ff ff 90 90 90 01 02 00 00 49 89 c6 48 8d 35 90 01 02 ff ff 48 89 df 31 d2 48 89 e9 e8 90 01 02 00 00 49 89 c4 48 89 df 31 f6 48 89 ea e8 90 01 02 00 00 48 89 44 24 28 48 8b 03 48 89 df 48 89 ee ff 90 90 90 } //01 02 
	condition:
		any of ($a_*)
 
}