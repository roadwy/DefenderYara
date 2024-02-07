
rule Backdoor_Win32_Bifrose_gen_D{
	meta:
		description = "Backdoor:Win32/Bifrose.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,66 00 64 00 0b 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 74 75 62 70 61 74 68 00 } //01 00 
		$a_00_1 = {70 6c 75 67 69 6e 31 2e 64 61 74 00 } //01 00  汰杵湩⸱慤t
		$a_00_2 = {53 4f 46 54 57 41 52 45 5c 57 67 65 74 00 } //01 00  体呆䅗䕒坜敧t
		$a_01_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  WriteProcessMemory
		$a_01_4 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //02 00  CreateRemoteThread
		$a_00_5 = {6b 69 78 4b 7a 6d 69 7c 6d 4b 69 78 7c 7d 7a 6d 5f 71 76 6c 77 7f 49 } //02 00 
		$a_00_6 = {70 69 66 00 73 63 72 00 65 78 65 00 } //02 00  楰f捳r硥e
		$a_01_7 = {c6 85 d7 fc ff ff 03 e9 83 00 00 00 83 bd 84 fe ff ff 04 75 7a 83 bd 88 fe ff ff 0a 75 09 c6 85 d7 fc ff ff 02 } //64 00 
		$a_03_8 = {f7 75 14 8b 45 10 8a 04 02 30 01 90 02 04 46 3b 75 0c 7c 90 09 15 00 90 02 0b 8b 45 08 90 03 01 01 31 33 d2 8d 0c 06 90 03 02 02 89 f0 8b c6 90 00 } //64 00 
		$a_01_9 = {57 8b 7c 24 0c 33 c9 85 ff 7e 28 53 8b 5c 24 18 55 8b 6c 24 18 56 8b 74 24 14 8b c1 33 d2 f7 f3 8a 04 2a 8a 14 31 32 d0 88 14 31 41 3b cf 7c ea } //64 00 
		$a_03_10 = {85 c0 0f 84 d4 f4 ff ff 68 f4 01 00 00 ff 15 90 01 04 8b 85 90 01 02 ff ff 50 b9 02 01 00 00 81 ec 90 01 02 00 00 8d b5 90 01 02 ff ff 8b fc f3 a5 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}