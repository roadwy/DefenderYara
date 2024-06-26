
rule TrojanClicker_Win32_RuPass_B{
	meta:
		description = "TrojanClicker:Win32/RuPass.B,SIGNATURE_TYPE_PEHSTR,17 01 15 01 18 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 61 74 65 6b 61 67 65 2e 69 66 72 61 6e 63 65 2e 63 6f 6d } //01 00  matekage.ifrance.com
		$a_01_1 = {6d 65 63 69 77 61 6d 65 2e 69 66 72 61 6e 63 65 2e 63 6f 6d } //01 00  meciwame.ifrance.com
		$a_01_2 = {70 65 63 69 70 69 78 69 2e 69 65 73 70 61 6e 61 2e 65 73 } //01 00  pecipixi.iespana.es
		$a_01_3 = {74 72 6f 6a 61 6e 65 72 2d 62 6f 61 72 64 2e 64 65 } //01 00  trojaner-board.de
		$a_01_4 = {66 6f 72 75 6d 2e 6b 61 73 70 65 72 73 6b 79 2e 63 6f 6d } //01 00  forum.kaspersky.com
		$a_01_5 = {63 61 73 74 6c 65 63 6f 70 73 2e 63 6f 6d } //01 00  castlecops.com
		$a_01_6 = {6e 61 6d 65 70 72 6f 73 2e 63 6f 6d } //01 00  namepros.com
		$a_01_7 = {61 73 6b 64 61 6d 61 67 65 2e 63 6f 6d } //01 00  askdamage.com
		$a_01_8 = {77 65 62 6d 61 73 74 65 72 77 6f 72 6c 64 2e 63 6f 6d } //01 00  webmasterworld.com
		$a_01_9 = {73 65 61 72 63 68 65 6e 67 69 6e 65 66 6f 72 75 6d 73 2e 63 6f 6d } //01 00  searchengineforums.com
		$a_01_10 = {6e 61 73 74 72 61 66 6f 72 75 6d 2e 63 6f 6d } //01 00  nastraforum.com
		$a_01_11 = {61 64 75 6c 74 77 65 62 6d 61 73 74 65 72 69 6e 66 6f 2e 63 6f 6d } //01 00  adultwebmasterinfo.com
		$a_01_12 = {62 6f 61 72 64 2e 67 6f 66 75 63 6b 79 6f 75 72 73 65 6c 66 2e 63 6f 6d } //01 00  board.gofuckyourself.com
		$a_01_13 = {75 6d 61 78 66 6f 72 75 6d 2e 63 6f 6d } //05 00  umaxforum.com
		$a_01_14 = {63 73 5f 63 6f 6e 66 69 67 5f 73 68 } //0a 00  cs_config_sh
		$a_01_15 = {47 65 74 50 72 6f 63 65 73 73 57 69 6e 64 6f 77 53 74 61 74 69 6f 6e } //0a 00  GetProcessWindowStation
		$a_01_16 = {7b 45 46 36 32 45 46 33 34 2d 37 45 35 41 2d 34 36 61 63 2d 39 33 38 33 2d 31 39 34 39 35 34 37 41 46 35 44 36 7d } //0a 00  {EF62EF34-7E5A-46ac-9383-1949547AF5D6}
		$a_01_17 = {2e 00 5c 00 6d 00 64 00 35 00 2e 00 63 00 70 00 70 00 } //0a 00  .\md5.cpp
		$a_01_18 = {43 00 53 00 5f 00 52 00 65 00 73 00 70 00 32 00 } //0a 00  CS_Resp2
		$a_01_19 = {52 00 65 00 73 00 70 00 31 00 } //0a 00  Resp1
		$a_01_20 = {52 00 65 00 71 00 75 00 65 00 73 00 74 00 } //0a 00  Request
		$a_01_21 = {43 00 53 00 5f 00 4d 00 75 00 74 00 65 00 78 00 } //64 00  CS_Mutex
		$a_01_22 = {43 6f 6e 6e 65 63 74 69 6f 6e 53 65 72 76 69 63 65 73 } //64 00  ConnectionServices
		$a_01_23 = {7b 36 44 37 42 32 31 31 41 2d 38 38 45 41 2d 34 39 30 63 2d 42 41 42 39 2d 33 36 30 30 44 38 44 37 43 35 30 33 7d } //00 00  {6D7B211A-88EA-490c-BAB9-3600D8D7C503}
	condition:
		any of ($a_*)
 
}