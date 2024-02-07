
rule TrojanSpy_Win32_Embed_B{
	meta:
		description = "TrojanSpy:Win32/Embed.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {40 89 45 f8 03 c0 83 c0 03 24 fc e8 90 01 04 8b c4 ff 75 f8 89 45 f0 50 6a ff ff 75 fc 66 89 18 90 00 } //01 00 
		$a_01_1 = {48 74 74 70 5f 64 6c 6c 2e 64 6c 6c 00 } //01 00 
		$a_01_2 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 46 00 72 00 61 00 6d 00 65 00 57 00 6f 00 72 00 6b 00 20 00 21 00 7e 00 00 00 } //01 00 
		$a_01_3 = {2f 77 69 6e 64 6f 77 73 2f 75 70 64 61 74 65 2f 73 65 61 72 63 68 3f 68 6c 3d 25 73 26 71 3d 25 73 26 6d 65 74 61 3d 25 73 26 69 64 3d 25 73 } //01 00  /windows/update/search?hl=%s&q=%s&meta=%s&id=%s
		$a_01_4 = {6e 65 74 73 74 61 74 20 2d 61 6e 6f 20 3e 3e } //01 00  netstat -ano >>
		$a_01_5 = {57 68 61 74 54 68 65 46 75 63 6b 69 6e 67 49 73 47 6f 69 6e 67 4f 6e 48 69 4d 61 6e 21 00 } //00 00  桗瑡桔䙥捵楫杮獉潇湩佧䡮䵩湡!
	condition:
		any of ($a_*)
 
}