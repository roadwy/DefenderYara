
rule TrojanSpy_Win32_Blackmonay_A{
	meta:
		description = "TrojanSpy:Win32/Blackmonay.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0b 00 0a 00 00 02 00 "
		
	strings :
		$a_01_0 = {42 6c 61 63 6b 4d 6f 6f 6e 20 52 75 6e 54 69 6d 65 } //02 00  BlackMoon RunTime
		$a_01_1 = {70 61 67 65 5f 61 6c 65 72 74 28 29 7b 72 65 74 75 72 6e 3b 7d } //02 00  page_alert(){return;}
		$a_01_2 = {3c 69 6e 70 75 74 20 74 79 70 65 3d 68 69 64 64 65 6e 20 69 64 3d 22 64 64 64 62 68 22 20 6e 61 6d 65 3d 22 64 64 64 62 68 22 20 76 61 6c 75 65 3d } //02 00  <input type=hidden id="dddbh" name="dddbh" value=
		$a_01_3 = {26 42 61 6e 6b 3d 49 43 42 43 26 4d 6f 6e 65 79 3d 38 38 } //02 00  &Bank=ICBC&Money=88
		$a_01_4 = {41 70 69 2f 31 36 33 2f 50 6f 73 74 2e 50 68 70 3f 55 73 65 72 4e 61 6d 65 3d } //02 00  Api/163/Post.Php?UserName=
		$a_01_5 = {63 75 74 5f 74 69 70 73 3d 31 26 72 64 6f 3d 72 64 6f 26 67 61 6d 65 69 64 3d 26 5f 73 65 72 76 65 72 5f 69 64 } //01 00  cut_tips=1&rdo=rdo&gameid=&_server_id
		$a_01_6 = {41 4d 44 20 49 53 42 45 54 54 45 52 } //01 00  AMD ISBETTER
		$a_01_7 = {65 31 36 31 32 35 35 61 2d 33 37 63 33 2d 31 31 64 32 2d 62 63 61 61 2d 30 30 63 30 34 66 64 39 32 39 64 62 } //01 00  e161255a-37c3-11d2-bcaa-00c04fd929db
		$a_01_8 = {25 73 5c 25 73 5c 25 73 2e 6c 6e 6b } //01 00  %s\%s\%s.lnk
		$a_01_9 = {31 46 42 41 30 34 45 45 2d 33 30 32 34 2d 31 31 44 32 2d 38 46 31 46 2d 30 30 30 30 46 38 37 41 42 44 31 36 } //00 00  1FBA04EE-3024-11D2-8F1F-0000F87ABD16
	condition:
		any of ($a_*)
 
}