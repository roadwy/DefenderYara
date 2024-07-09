
rule TrojanDownloader_Win32_Esendi_B{
	meta:
		description = "TrojanDownloader:Win32/Esendi.B,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 05 00 00 "
		
	strings :
		$a_00_0 = {81 e2 ff ff ff 7f 33 94 84 d8 09 00 00 8b ca 80 e1 01 0f b6 c9 f7 d9 1b c9 d1 ea 81 e1 df b0 08 99 33 8c 84 0c 10 00 00 33 ca 89 4c 84 18 40 3d e3 00 00 00 7c bc 3d 6f 02 00 00 7d 47 0f 1f 00 } //10
		$a_00_1 = {81 e2 ff ff ff 7f 33 94 84 d8 09 00 00 8b ca 80 e1 01 0f b6 c9 f7 d9 1b c9 d1 ea 81 e1 df b0 08 99 33 8c 84 8c fc ff ff 33 ca 89 4c 84 18 40 3d 6f 02 00 00 } //10
		$a_00_2 = {8d 14 85 00 00 00 00 8b 8c 14 d8 09 00 00 33 4c 24 18 81 e1 ff ff ff 7f 33 8c 14 d8 09 00 00 8b c1 24 01 0f b6 c0 f7 d8 1b c0 d1 e9 25 df b0 08 99 33 c1 33 84 24 48 06 00 00 33 f6 89 44 14 18 89 74 24 14 } //10
		$a_00_3 = {6b 4d 08 0c 83 ca ff 81 7d 08 55 55 55 15 0f 47 ca 51 } //10
		$a_03_4 = {33 ff b8 c5 9d 1c 81 8b d5 8d 4d ?? 3b cd 1b db 83 e3 fc 83 c3 04 3b e9 } //10
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_03_4  & 1)*10) >=30
 
}