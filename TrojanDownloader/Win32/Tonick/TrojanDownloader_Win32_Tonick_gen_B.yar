
rule TrojanDownloader_Win32_Tonick_gen_B{
	meta:
		description = "TrojanDownloader:Win32/Tonick.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0c 00 05 00 00 0a 00 "
		
	strings :
		$a_03_0 = {66 33 45 d0 0f bf d0 52 ff 15 90 01 04 8b d0 8d 4d c8 ff 15 90 01 04 50 ff 15 90 01 04 8b d0 8d 4d d4 ff 15 90 00 } //0a 00 
		$a_03_1 = {66 33 45 d0 0f bf c0 50 e8 90 01 04 8b d0 8d 4d c8 e8 90 01 04 50 e8 90 01 04 8b d0 8d 4d d4 e8 90 00 } //0a 00 
		$a_03_2 = {6b 70 ff fb 12 e7 0b 90 01 01 00 04 00 23 44 ff 2a 31 74 ff 32 04 00 48 ff 44 ff 35 4c ff 00 0c 6b 70 ff f3 ff 00 c6 1c 90 01 02 00 07 f4 01 70 70 ff 1e 90 01 02 00 0b 6b 70 ff f4 01 a9 70 70 ff 00 0a 04 72 ff 64 6c 90 00 } //02 00 
		$a_01_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  WriteProcessMemory
		$a_01_4 = {5d 00 71 00 75 00 67 00 6d 00 69 00 74 00 7c 00 27 00 6f 00 73 00 69 00 } //00 00  ]qugmit|'osi
	condition:
		any of ($a_*)
 
}