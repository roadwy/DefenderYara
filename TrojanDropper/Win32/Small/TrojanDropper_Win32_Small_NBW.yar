
rule TrojanDropper_Win32_Small_NBW{
	meta:
		description = "TrojanDropper:Win32/Small.NBW,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 3a 5c 54 45 4d 50 5c } //01 00  C:\TEMP\
		$a_00_1 = {65 68 33 34 74 67 } //01 00  eh34tg
		$a_02_2 = {6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 ff 75 10 ff 15 90 01 04 89 45 f4 6a 00 68 80 00 00 00 6a 02 6a 00 6a 02 68 00 00 00 40 ff 75 14 ff 15 90 01 04 89 45 fc 83 7d f4 ff 74 06 83 7d fc ff 75 07 32 c0 e9 90 01 04 6a 00 6a 00 ff 75 08 ff 75 f4 ff 15 90 01 04 83 65 f0 00 83 7d 0c 00 0f 86 90 01 04 81 7d 0c 00 40 00 00 72 90 01 01 6a 00 8d 45 f8 50 68 00 40 00 00 ff 75 ec ff 75 f4 ff 15 90 01 04 83 65 e4 00 eb 07 8b 45 e4 40 89 45 e4 8b 45 e4 3b 45 f8 90 00 } //01 00 
		$a_02_3 = {0f b7 c0 99 6a 05 59 f7 f9 83 c2 07 52 8d 85 90 01 04 50 ff 15 90 01 04 8d 84 05 90 01 04 50 e8 90 01 04 59 59 68 90 01 04 8d 85 90 01 04 50 ff 15 90 00 } //01 00 
		$a_02_4 = {be f4 10 40 00 8d bd a0 fc ff ff a5 66 a5 a4 33 c0 8d bd a7 fc ff ff aa 68 fc 10 40 00 8d 85 a0 fc ff ff 50 ff 15 90 01 04 8d 45 c4 50 ff 15 90 01 04 85 c0 74 2e 6a 40 ff 75 fc ff 15 90 01 04 6a 01 ff 75 fc ff 15 90 01 04 6a 00 8d 85 b0 fd ff ff 50 6a 05 6a 04 ff 15 90 01 04 33 c0 40 eb 20 6a 20 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}