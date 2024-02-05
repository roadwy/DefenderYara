
rule TrojanSpy_Win32_Keylogger_CC{
	meta:
		description = "TrojanSpy:Win32/Keylogger.CC,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 72 69 6e 67 2e 74 78 74 00 } //01 00 
		$a_01_1 = {68 65 6c 6f 20 6d 65 2e 73 6f 6d 65 70 61 6c 61 63 65 2e 63 6f 6d 0a 00 } //01 00 
		$a_03_2 = {c7 45 fc 00 00 00 00 8b 45 08 89 04 24 e8 90 01 02 00 00 3b 45 fc 76 1e 8b 45 08 8b 4d fc 01 c1 8b 45 08 8b 55 fc 01 c2 8b 45 0c 02 02 88 01 8d 45 fc ff 00 eb d2 90 00 } //01 00 
		$a_03_3 = {ff ff 08 00 66 81 bd 90 01 02 ff ff de 00 0f 8f 11 04 00 00 0f bf 85 90 01 02 ff ff 89 04 24 a1 10 50 40 00 ff d0 83 ec 04 66 3d 01 80 0f 85 df 03 00 00 66 83 bd 90 01 02 ff ff 26 7e 48 66 83 bd 90 01 02 ff ff 40 7f 3e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}