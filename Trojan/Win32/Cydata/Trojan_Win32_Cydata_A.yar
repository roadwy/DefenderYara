
rule Trojan_Win32_Cydata_A{
	meta:
		description = "Trojan:Win32/Cydata.A,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 05 00 00 0a 00 "
		
	strings :
		$a_00_0 = {63 74 5f 69 6e 69 74 3a 20 6c 65 6e 67 74 68 20 21 3d 20 32 35 36 } //0a 00  ct_init: length != 256
		$a_00_1 = {63 74 5f 69 6e 69 74 3a 20 32 35 36 2b 64 69 73 74 20 21 3d 20 35 31 32 } //01 00  ct_init: 256+dist != 512
		$a_00_2 = {68 74 74 70 73 3a 2f 2f 63 62 69 2e 68 61 6e 79 61 6e 67 2e 61 63 2e 6b 72 2f 73 6b 69 6e 2f 70 61 67 65 2f 62 6f 61 72 64 2e 61 73 70 } //01 00  https://cbi.hanyang.ac.kr/skin/page/board.asp
		$a_00_3 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 61 73 70 73 2e 63 6f 2e 6b 72 2f 6d 65 64 69 61 2f 76 69 65 77 2e 61 73 70 } //0a 00  https://www.asps.co.kr/media/view.asp
		$a_02_4 = {8b 5d f8 53 e8 90 01 04 8b f0 83 c4 04 85 f6 74 26 8b c3 8d 50 01 8d a4 24 00 00 00 00 8a 08 40 84 c9 75 f9 2b c2 50 56 53 e8 90 01 04 56 e8 90 01 04 83 c4 10 33 f6 8d 64 24 00 53 ff 15 90 01 04 8b f8 85 ff 75 08 6a 64 ff 15 90 01 04 46 85 ff 75 05 83 fe 04 7c e1 33 db 8b 4d fc 51 57 ff 15 90 01 04 8b f0 85 f6 75 08 6a 64 ff 15 90 01 04 43 85 f6 75 05 83 fb 04 7c dd 8b 55 fc 52 e8 90 01 04 8b 45 f8 50 e8 90 01 04 8b 7d f4 83 c4 08 89 77 04 5f 8b c6 5e 5b 8b e5 5d c3 85 c0 74 09 50 e8 90 01 04 83 c4 04 33 f6 89 77 04 8b 47 04 5f 5e 5b 8b e5 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}