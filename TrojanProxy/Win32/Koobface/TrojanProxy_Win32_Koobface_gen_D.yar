
rule TrojanProxy_Win32_Koobface_gen_D{
	meta:
		description = "TrojanProxy:Win32/Koobface.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,21 00 21 00 0a 00 00 0a 00 "
		
	strings :
		$a_00_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e } //0a 00  Software\Microsoft\Internet Explorer\Main
		$a_01_1 = {6d 65 27 2b 27 74 68 27 2b 27 6f 64 3d 22 50 27 2b 27 6f 53 27 2b 27 54 27 } //0a 00  me'+'th'+'od="P'+'oS'+'T'
		$a_01_2 = {47 45 25 73 35 30 2f 25 73 3d 25 64 26 73 3d 25 63 26 75 69 64 3d 25 6c 64 26 70 3d 25 64 26 69 70 3d 25 73 26 71 3d 25 73 } //01 00  GE%s50/%s=%d&s=%c&uid=%ld&p=%d&ip=%s&q=%s
		$a_00_3 = {73 61 2e 61 6f 6c 2e 63 6f 6d } //01 00  sa.aol.com
		$a_00_4 = {79 61 68 6f 6f 61 70 69 73 2e 63 6f 6d } //01 00  yahooapis.com
		$a_00_5 = {6d 65 74 61 63 61 66 65 2e 63 6f 6d } //01 00  metacafe.com
		$a_00_6 = {79 69 6d 67 2e 63 6f 6d } //01 00  yimg.com
		$a_00_7 = {69 6d 67 2e 79 6f 75 74 75 62 65 2e 63 6f 6d } //01 00  img.youtube.com
		$a_00_8 = {73 75 67 67 2e 73 65 61 72 63 68 } //01 00  sugg.search
		$a_00_9 = {73 65 61 72 63 68 2e 6d 64 6e } //00 00  search.mdn
	condition:
		any of ($a_*)
 
}