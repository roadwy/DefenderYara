
rule Worm_Win32_DuiskBot{
	meta:
		description = "Worm:Win32/DuiskBot,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 1b 00 00 "
		
	strings :
		$a_01_0 = {65 2d 67 6f 6c 64 } //1 e-gold
		$a_01_1 = {53 4f 43 4b 53 34 } //1 SOCKS4
		$a_01_2 = {53 63 61 6e 6e 69 6e 67 20 25 73 2e } //1 Scanning %s.
		$a_00_3 = {59 61 68 6f 6f 42 75 64 64 79 4d 61 69 6e } //1 YahooBuddyMain
		$a_01_4 = {7b 53 4e 49 46 46 45 52 7d 3a } //1 {SNIFFER}:
		$a_00_5 = {57 65 6c 6c 73 20 46 61 72 67 6f } //1 Wells Fargo
		$a_01_6 = {67 6f 6f 67 6c 65 2e 63 6f 6d 2f 75 72 6c 3f 71 3d 68 74 74 70 3a 2f 2f 25 73 3a 25 64 } //2 google.com/url?q=http://%s:%d
		$a_01_7 = {26 64 65 6c 20 43 6f 6f 6b 69 65 73 5c 2a 2e 74 78 74 3e 4e 55 4c } //2 &del Cookies\*.txt>NUL
		$a_01_8 = {25 73 5c 64 6c 6c 63 61 63 68 65 5c 25 73 } //2 %s\dllcache\%s
		$a_01_9 = {2a 40 66 62 69 2e 67 6f 76 } //2 *@fbi.gov
		$a_01_10 = {45 78 70 6c 6f 69 74 65 64 } //2 Exploited
		$a_00_11 = {49 4d 57 69 6e 64 6f 77 43 6c 61 73 73 } //2 IMWindowClass
		$a_00_12 = {4d 53 4e 48 69 64 64 65 6e 57 69 6e 64 6f 77 43 6c 61 73 73 } //2 MSNHiddenWindowClass
		$a_00_13 = {49 45 2d 56 4d 4c 00 } //2
		$a_01_14 = {3a 69 6d 61 67 65 3e 3c 4d 65 74 61 53 70 6c 6f 69 74 3a } //2 :image><MetaSploit:
		$a_01_15 = {25 64 25 64 25 64 5f 76 6d 6c 2e } //3 %d%d%d_vml.
		$a_01_16 = {53 70 72 65 61 64 7d 3a 20 25 64 } //4 Spread}: %d
		$a_01_17 = {6e 65 74 20 73 74 6f 70 20 22 4e 6f 72 74 6f 6e } //4 net stop "Norton
		$a_01_18 = {25 75 39 30 39 30 25 75 39 30 39 30 25 75 39 30 39 30 25 75 43 43 45 39 25 75 } //5 %u9090%u9090%u9090%uCCE9%u
		$a_01_19 = {7b 52 45 56 45 52 53 45 2d 43 4d 44 7d 3a } //3 {REVERSE-CMD}:
		$a_01_20 = {7b 49 4d 53 50 52 45 41 44 7d 3a } //4 {IMSPREAD}:
		$a_01_21 = {5b 4e 4d 4c 4b 5d 00 5b 4e 4d 4c 4b 5d 00 } //5 乛䱍嵋嬀䵎䭌]
		$a_01_22 = {32 4b 00 00 7b 53 59 53 49 4e 46 4f 7d 3a } //5
		$a_01_23 = {6a 70 67 00 69 73 6f 00 6d 70 33 00 70 64 66 00 } //5 灪g獩o灭3摰f
		$a_01_24 = {55 49 44 3d 25 73 3b 50 57 44 3d 25 73 3b 25 73 } //5 UID=%s;PWD=%s;%s
		$a_01_25 = {3a 2a 21 2a 40 2a 20 2a 20 2a 20 3a 2a 73 79 6e } //5 :*!*@* * * :*syn
		$a_01_26 = {3a 25 6c 73 00 00 50 61 73 73 70 6f 72 74 2e 4e } //5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2+(#a_01_10  & 1)*2+(#a_00_11  & 1)*2+(#a_00_12  & 1)*2+(#a_00_13  & 1)*2+(#a_01_14  & 1)*2+(#a_01_15  & 1)*3+(#a_01_16  & 1)*4+(#a_01_17  & 1)*4+(#a_01_18  & 1)*5+(#a_01_19  & 1)*3+(#a_01_20  & 1)*4+(#a_01_21  & 1)*5+(#a_01_22  & 1)*5+(#a_01_23  & 1)*5+(#a_01_24  & 1)*5+(#a_01_25  & 1)*5+(#a_01_26  & 1)*5) >=12
 
}