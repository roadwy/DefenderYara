
rule PWS_Win32_OnLineGames_ABH{
	meta:
		description = "PWS:Win32/OnLineGames.ABH,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 13 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 64 61 74 61 5c 69 64 2e 69 6e 69 } //01 00  \data\id.ini
		$a_00_1 = {41 31 42 32 43 33 } //01 00  A1B2C3
		$a_00_2 = {3f 61 63 74 69 6f 6e 3d 67 65 74 70 6f 73 26 4e 61 6d 65 3d } //01 00  ?action=getpos&Name=
		$a_00_3 = {52 65 61 64 6d 62 2e 61 73 70 } //01 00  Readmb.asp
		$a_00_4 = {67 6f 6c 64 5f 63 6f 69 6e } //01 00  gold_coin
		$a_00_5 = {62 61 6c 61 6e 63 65 } //01 00  balance
		$a_00_6 = {6c 65 76 65 6c } //01 00  level
		$a_00_7 = {3f 67 61 6d 65 54 79 70 65 } //01 00  ?gameType
		$a_01_8 = {26 53 65 72 76 65 72 3d 25 73 } //01 00  &Server=%s
		$a_01_9 = {26 5a 6f 6e 65 3d 25 73 } //01 00  &Zone=%s
		$a_00_10 = {26 4e 61 6d 65 3d 25 73 26 70 61 73 73 77 6f 72 64 3d 25 73 26 } //01 00  &Name=%s&password=%s&
		$a_00_11 = {6e 69 63 6b 4e 61 6d 65 3d 25 73 26 4c 65 76 65 6c 3d 25 73 26 4d 6f 6e 65 79 3d 25 73 26 } //01 00  nickName=%s&Level=%s&Money=%s&
		$a_00_12 = {73 65 63 6f 50 61 73 73 3d 25 73 26 4d 42 3d 25 73 26 62 61 6e 6b 50 61 73 73 3d 25 73 26 6e 6f 52 65 66 72 65 73 68 43 6f 64 65 3d 25 73 26 70 61 72 61 3d 25 73 26 76 65 72 3d 25 73 } //01 00  secoPass=%s&MB=%s&bankPass=%s&noRefreshCode=%s&para=%s&ver=%s
		$a_00_13 = {5c 64 61 74 61 5c 63 6f 6e 66 69 67 2e 69 6e 69 } //01 00  \data\config.ini
		$a_00_14 = {61 73 6b 74 61 6f 2e 6d 6f 64 } //01 00  asktao.mod
		$a_00_15 = {33 36 30 53 61 66 65 2e 65 78 65 } //01 00  360Safe.exe
		$a_00_16 = {33 36 30 54 72 61 79 2e 65 78 65 } //01 00  360Tray.exe
		$a_00_17 = {5a 6f 6e 65 4c 69 6e 6b } //01 00  ZoneLink
		$a_00_18 = {41 75 74 6f 55 70 64 61 74 65 } //00 00  AutoUpdate
	condition:
		any of ($a_*)
 
}