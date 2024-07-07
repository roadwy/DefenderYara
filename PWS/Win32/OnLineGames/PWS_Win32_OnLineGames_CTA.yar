
rule PWS_Win32_OnLineGames_CTA{
	meta:
		description = "PWS:Win32/OnLineGames.CTA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {50 6a 01 8d 85 90 90 fc ff ff 53 50 ff 75 f0 ff 15 90 01 04 ff 75 f0 ff d6 8d 45 ec c7 85 60 ff ff ff 53 4f 46 54 50 8d 85 60 ff ff ff 50 68 02 00 00 80 c7 85 64 ff ff ff 57 41 52 45 c7 85 68 ff ff ff 5c 4d 69 63 c7 85 6c ff ff ff 72 6f 73 6f c7 85 70 ff ff ff 66 74 5c 57 c7 85 74 ff ff ff 69 6e 64 6f c7 85 78 ff ff ff 77 73 5c 43 c7 85 7c ff ff ff 75 72 72 65 c7 45 80 6e 74 56 65 c7 45 84 72 73 69 6f c7 45 88 6e 5c 45 78 c7 45 8c 70 6c 6f 72 c7 45 90 90 65 72 5c 53 c7 45 94 68 65 6c 6c c7 45 98 45 78 65 63 c7 45 9c 75 74 65 48 c7 45 a0 6f 6f 6b 73 89 5d a4 ff d7 90 00 } //1
		$a_00_1 = {33 db c7 45 e4 54 41 32 45 c7 45 e8 64 69 74 00 89 5d ec c7 45 d4 54 46 72 6d c7 45 d8 4c 6f 67 4f c7 45 dc 6e 00 00 00 89 5d e0 8d 45 d4 53 50 53 } //1
		$a_02_2 = {33 ff 8d 45 e0 57 50 57 ff 35 90 01 04 c7 45 e0 54 46 72 6d c7 45 e4 50 61 73 73 c7 45 e8 45 74 63 00 89 7d ec c7 45 f0 54 41 32 45 c7 45 f4 64 69 74 00 89 7d f8 ff d6 8b d8 8d 45 f0 57 50 57 53 ff d6 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=2
 
}