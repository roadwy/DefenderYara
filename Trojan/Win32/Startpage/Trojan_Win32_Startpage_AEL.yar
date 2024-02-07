
rule Trojan_Win32_Startpage_AEL{
	meta:
		description = "Trojan:Win32/Startpage.AEL,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 02 00 "
		
	strings :
		$a_01_0 = {77 77 77 2e 78 69 68 61 6f 2e 6e 65 74 2f 30 33 33 2f 74 61 6f 62 61 6f 2e 68 74 6d 6c } //01 00  www.xihao.net/033/taobao.html
		$a_01_1 = {5c d7 c0 c3 e6 5c cc d4 b1 a6 2d cc d8 c2 f4 2e } //01 00 
		$a_01_2 = {5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e 00 } //01 00  䥜瑮牥敮⁴硅汰牯牥䵜楡n
		$a_01_3 = {00 53 74 61 72 74 20 50 61 67 65 00 } //01 00  匀慴瑲倠条e
		$a_01_4 = {68 6f 6f 6b 2e 64 6c 6c } //01 00  hook.dll
		$a_01_5 = {74 61 6f 62 61 6f 2e 69 63 6f 27 } //01 00  taobao.ico'
		$a_01_6 = {5c 6c 76 65 67 6e 65 64 5c 63 6f 6e 66 69 67 2e 69 6e 69 } //00 00  \lvegned\config.ini
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Startpage_AEL_2{
	meta:
		description = "Trojan:Win32/Startpage.AEL,SIGNATURE_TYPE_PEHSTR,08 00 08 00 07 00 00 02 00 "
		
	strings :
		$a_01_0 = {5c 54 65 6e 63 65 6e 74 5c 54 65 6e 63 65 6e 74 54 72 61 76 65 6c 65 72 5c 31 30 30 5c 66 61 76 69 63 6f 6e } //02 00  \Tencent\TencentTraveler\100\favicon
		$a_01_1 = {5c 53 6f 67 6f 75 45 78 70 6c 6f 72 65 72 5c 46 61 76 49 63 6f 6e } //01 00  \SogouExplorer\FavIcon
		$a_01_2 = {46 61 76 6f 72 69 74 65 32 2e 64 61 74 } //01 00  Favorite2.dat
		$a_01_3 = {6e 61 76 69 6e 66 6f 2e 64 62 } //01 00  navinfo.db
		$a_01_4 = {68 74 74 70 5f 77 77 77 2e 39 37 37 39 36 2e 63 6e 5f 38 30 5f 66 61 76 2e 69 63 6f } //01 00  http_www.97796.cn_80_fav.ico
		$a_01_5 = {77 77 77 2e 32 35 34 38 2e 63 6e 5f 66 61 76 69 63 6f 6e 2e 69 63 6f } //01 00  www.2548.cn_favicon.ico
		$a_01_6 = {68 74 74 70 3a 2f 2f 77 77 77 2e 32 35 34 38 2e 63 6e 2f 3f } //00 00  http://www.2548.cn/?
	condition:
		any of ($a_*)
 
}