
rule TrojanDownloader_Win32_Hokeydaph_A{
	meta:
		description = "TrojanDownloader:Win32/Hokeydaph.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {e9 14 01 00 00 b8 63 00 00 00 66 89 85 70 e7 ff ff b9 3a 00 00 00 66 89 8d 72 e7 ff ff ba 5c } //4
		$a_01_1 = {0f b7 85 6e ff ff ff 99 b9 07 00 00 00 f7 f9 83 c0 01 66 89 85 60 ff ff ff 0f bf 95 60 ff ff ff 83 fa 05 75 12 } //4
		$a_00_2 = {42 00 69 00 64 00 3a 00 20 00 25 00 73 00 } //2 Bid: %s
		$a_00_3 = {48 00 69 00 64 00 3a 00 20 00 25 00 73 00 } //2 Hid: %s
		$a_00_4 = {45 00 6c 00 65 00 76 00 61 00 74 00 69 00 6f 00 6e 00 3a 00 41 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00 21 00 6e 00 65 00 77 00 3a 00 7b 00 33 00 61 00 64 00 30 00 35 00 35 00 37 00 35 00 2d 00 38 00 38 00 35 00 37 00 2d 00 34 00 38 00 35 00 30 00 2d 00 39 00 32 00 37 00 37 00 2d 00 31 00 31 00 62 00 38 00 35 00 62 00 64 00 62 00 38 00 65 00 30 00 39 00 7d 00 } //1 Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*1) >=6
 
}