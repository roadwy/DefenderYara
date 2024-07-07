
rule TrojanDownloader_Win32_Rispere{
	meta:
		description = "TrojanDownloader:Win32/Rispere,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 04 00 00 "
		
	strings :
		$a_03_0 = {66 33 45 d0 0f bf d0 52 ff 15 90 01 04 8b d0 8d 4d c8 ff 15 90 01 04 50 ff 15 90 01 04 8b d0 8d 4d d4 ff 15 90 00 } //10
		$a_03_1 = {6b 70 ff fb 12 e7 0b 90 01 01 00 04 00 23 44 ff 2a 31 74 ff 32 04 00 48 ff 44 ff 35 4c ff 00 0c 6b 70 ff f3 ff 00 c6 1c 90 01 02 00 07 f4 01 70 70 ff 1e 90 01 02 00 0b 6b 70 ff f4 01 a9 70 70 ff 00 0a 04 72 ff 64 6c 90 00 } //10
		$a_00_2 = {6b 56 ff f4 02 c6 1c 4c 00 00 19 1b 01 00 43 50 ff 04 50 ff 0b 02 00 04 00 fd e7 08 00 00 00 2f 50 ff 1e 70 00 00 0b 6b 56 ff f4 01 c6 1c 70 00 00 19 } //5
		$a_00_3 = {6c 00 61 00 2e 00 35 00 34 00 36 00 2a 00 39 00 } //5 la.546*9
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_00_2  & 1)*5+(#a_00_3  & 1)*5) >=15
 
}