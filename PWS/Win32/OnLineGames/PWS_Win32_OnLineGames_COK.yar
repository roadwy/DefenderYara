
rule PWS_Win32_OnLineGames_COK{
	meta:
		description = "PWS:Win32/OnLineGames.COK,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0d 00 05 00 00 "
		
	strings :
		$a_00_0 = {49 6e 74 65 72 6e 65 74 52 65 61 64 } //1 InternetRead
		$a_00_1 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //1 CallNextHookEx
		$a_00_2 = {78 79 32 2e 65 78 65 00 71 71 67 61 6d 65 2e 65 78 65 00 00 71 71 2e 65 78 65 00 } //4
		$a_00_3 = {25 73 3f 6b 73 3d 73 62 39 26 69 64 3d 25 73 26 70 3d 25 73 26 71 3d 25 73 26 6c 63 6b 3d 25 73 26 73 72 76 3d 25 73 26 6a 73 31 3d 25 73 26 69 64 31 3d 25 73 26 64 6a 31 3d 25 73 26 70 63 3d 25 73 } //4 %s?ks=sb9&id=%s&p=%s&q=%s&lck=%s&srv=%s&js1=%s&id1=%s&dj1=%s&pc=%s
		$a_02_4 = {c7 45 f0 6c 69 6e 6b 50 8d 85 0c ff ff ff 50 c7 45 f4 2e 00 00 00 ff 15 90 01 04 59 59 5f 5e 5b 85 c0 74 2f 8b 40 05 c7 45 ec 77 6f 72 00 25 ff ff ff 00 c7 45 f0 77 32 69 00 c7 45 f4 7a 68 75 00 90 00 } //4
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*4+(#a_00_3  & 1)*4+(#a_02_4  & 1)*4) >=13
 
}