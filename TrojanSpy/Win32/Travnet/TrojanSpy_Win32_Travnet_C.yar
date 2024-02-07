
rule TrojanSpy_Win32_Travnet_C{
	meta:
		description = "TrojanSpy:Win32/Travnet.C,SIGNATURE_TYPE_PEHSTR_EXT,ffffff97 00 ffffff8d 00 09 00 00 64 00 "
		
	strings :
		$a_01_0 = {74 72 61 76 6c 65 72 62 61 63 6b 69 6e 66 6f 2d 25 64 2d 25 64 2d 25 64 2d 25 64 2d 25 64 2e 64 6c 6c 00 } //14 00 
		$a_01_1 = {25 73 5c 73 79 73 74 65 6d 5f 74 2e 64 6c 6c 00 } //14 00 
		$a_01_2 = {25 73 5c 73 79 73 74 65 6d 5c 63 6f 6e 66 69 67 5f 74 2e 64 61 74 00 } //05 00 
		$a_00_3 = {25 73 3f 61 63 74 69 6f 6e 3d 67 65 74 63 6d 64 26 68 6f 73 74 69 64 3d 25 73 26 68 6f 73 74 6e 61 6d 65 3d 25 73 } //05 00  %s?action=getcmd&hostid=%s&hostname=%s
		$a_00_4 = {64 31 3d 25 73 0a 64 69 72 63 6f 75 6e 74 3d 31 } //01 00  ㅤ┽ੳ楤捲畯瑮ㄽ
		$a_00_5 = {6e 74 76 62 61 30 30 2e 74 6d 70 5c } //01 00  ntvba00.tmp\
		$a_00_6 = {25 73 5c 75 65 6e 75 6d 66 73 2e 69 6e 69 } //01 00  %s\uenumfs.ini
		$a_00_7 = {64 6e 6c 69 73 74 2e 69 6e 69 } //01 00  dnlist.ini
		$a_00_8 = {5c 73 74 61 74 5f 74 2e 69 6e 69 } //00 00  \stat_t.ini
		$a_00_9 = {5d 04 00 00 48 07 03 80 5c 21 00 00 49 07 03 80 00 00 01 00 04 00 0b 00 88 21 54 72 61 76 6e 65 74 2e 41 00 00 01 40 05 82 5c 00 04 00 e7 42 00 00 00 00 3e 00 67 fc c7 0f e3 0f 17 05 ec ed f2 3f 88 74 78 0f 0b bc 19 3f 80 1e fe e3 8f a3 c7 0f 93 ec 0f 0b ac ce bc 3f d7 ac 1a 3f ea ac bc 13 80 0b ec ed } //f2 3f 
	condition:
		any of ($a_*)
 
}