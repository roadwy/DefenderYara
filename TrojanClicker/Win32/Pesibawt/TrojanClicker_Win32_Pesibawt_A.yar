
rule TrojanClicker_Win32_Pesibawt_A{
	meta:
		description = "TrojanClicker:Win32/Pesibawt.A,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 12 00 00 03 00 "
		
	strings :
		$a_01_0 = {2f 70 62 70 72 6f 2f 73 74 61 74 73 2f 63 6e 74 2e 70 68 70 3f 74 79 70 65 3d 25 73 26 73 61 69 64 3d 25 73 26 76 65 72 3d 25 73 } //03 00  /pbpro/stats/cnt.php?type=%s&said=%s&ver=%s
		$a_01_1 = {26 00 23 00 78 00 61 00 30 00 3b 00 3c 00 73 00 63 00 72 00 69 00 70 00 74 00 3e 00 66 00 75 00 6e 00 63 00 74 00 69 00 6f 00 6e 00 } //02 00  &#xa0;<script>function
		$a_01_2 = {50 70 63 42 6f 74 50 72 6f } //01 00  PpcBotPro
		$a_01_3 = {44 61 69 6c 79 53 65 61 72 63 68 65 73 } //01 00  DailySearches
		$a_01_4 = {44 61 69 6c 79 43 6c 69 63 6b 73 } //01 00  DailyClicks
		$a_01_5 = {63 5f 73 65 61 72 63 68 } //01 00  c_search
		$a_01_6 = {63 5f 63 6c 69 63 6b } //01 00  c_click
		$a_01_7 = {4d 00 79 00 57 00 65 00 62 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 } //01 00  MyWebDocument
		$a_01_8 = {4d 00 79 00 57 00 65 00 62 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 48 00 6f 00 73 00 74 00 } //01 00  MyWebBrowserHost
		$a_01_9 = {26 71 3d 7b 4b 45 59 57 4f 52 44 7d 26 62 74 6e 47 } //01 00  &q={KEYWORD}&btnG
		$a_01_10 = {26 71 3d 7b 4b 45 59 57 4f 52 44 7d 26 6c 72 3d } //01 00  &q={KEYWORD}&lr=
		$a_01_11 = {26 71 3d 7b 4b 45 59 57 4f 52 44 7d 26 73 70 65 6c 6c } //01 00  &q={KEYWORD}&spell
		$a_01_12 = {26 71 3d 7b 4b 45 59 57 4f 52 44 7d 26 73 74 61 72 74 } //01 00  &q={KEYWORD}&start
		$a_01_13 = {26 71 3d 7b 4b 45 59 57 4f 52 44 7d 7c 7c 63 6c 69 63 6b 2e 70 68 70 } //01 00  &q={KEYWORD}||click.php
		$a_01_14 = {26 71 3d 7b 4b 45 59 57 4f 52 44 7d 7c 7c 67 6f 2e 70 68 70 } //01 00  &q={KEYWORD}||go.php
		$a_01_15 = {3f 70 3d 7b 4b 45 59 57 4f 52 44 7d 26 65 69 } //01 00  ?p={KEYWORD}&ei
		$a_01_16 = {3f 71 3d 7b 4b 45 59 57 4f 52 44 7d 26 66 69 72 73 74 } //01 00  ?q={KEYWORD}&first
		$a_01_17 = {3f 71 3d 7b 4b 45 59 57 4f 52 44 7d 26 46 4f 52 4d } //00 00  ?q={KEYWORD}&FORM
	condition:
		any of ($a_*)
 
}