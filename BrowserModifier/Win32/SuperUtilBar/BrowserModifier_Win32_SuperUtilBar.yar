
rule BrowserModifier_Win32_SuperUtilBar{
	meta:
		description = "BrowserModifier:Win32/SuperUtilBar,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 1c 00 00 05 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 36 37 38 31 2e 63 6f 6d 2f 63 69 74 79 2f } //05 00  http://www.6781.com/city/
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 36 37 38 31 2e 63 6f 6d 2f 6e 61 76 68 74 6d 2f 6e 61 76 } //04 00  http://www.6781.com/navhtm/nav
		$a_01_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 73 68 69 79 6f 6e 67 73 6f 75 73 75 6f 2e 63 6f 6d } //05 00  http://www.shiyongsousuo.com
		$a_01_3 = {30 33 44 30 43 35 34 37 2d 45 42 41 44 2d 34 33 64 39 2d 38 42 35 37 2d 44 45 31 36 45 37 41 39 33 42 35 32 } //05 00  03D0C547-EBAD-43d9-8B57-DE16E7A93B52
		$a_01_4 = {36 37 38 31 54 6f 6f 6c 42 61 72 2e 64 6c 6c } //05 00  6781ToolBar.dll
		$a_01_5 = {73 75 70 65 72 75 74 69 6c 62 61 72 2e 64 6c 6c } //01 00  superutilbar.dll
		$a_01_6 = {20 68 74 74 70 3a 2f 2f 77 77 77 2e 69 6d 6f 62 69 6c 65 2e 63 6f 6d 2e 63 6e 2f } //01 00   http://www.imobile.com.cn/
		$a_01_7 = {20 68 74 74 70 3a 2f 2f 77 77 77 2e 73 74 6f 63 6b 73 74 61 72 2e 63 6f 6d 2f } //01 00   http://www.stockstar.com/
		$a_01_8 = {20 68 74 74 70 3a 2f 2f 77 77 77 2e 66 6c 61 73 68 65 6d 70 69 72 65 2e 63 6f 6d 2f } //01 00   http://www.flashempire.com/
		$a_01_9 = {20 68 74 74 70 3a 2f 2f 77 77 77 2e 64 69 61 6e 70 69 6e 67 2e 63 6f 6d 2f } //01 00   http://www.dianping.com/
		$a_01_10 = {20 68 74 74 70 3a 2f 2f 77 77 77 2e 70 63 6c 61 64 79 2e 63 6f 6d 2e 63 6e 2f } //01 00   http://www.pclady.com.cn/
		$a_01_11 = {20 68 74 74 70 3a 2f 2f 77 77 77 2e 39 36 33 33 33 2e 63 6f 6d 2f } //01 00   http://www.96333.com/
		$a_01_12 = {20 68 74 74 70 3a 2f 2f 77 77 77 2e 62 6f 6b 65 65 2e 63 6f 6d 2f } //01 00   http://www.bokee.com/
		$a_01_13 = {20 68 74 74 70 3a 2f 2f 77 77 77 2e 71 69 68 6f 6f 2e 63 6f 6d 2f } //01 00   http://www.qihoo.com/
		$a_01_14 = {20 68 74 74 70 3a 2f 2f 77 77 77 2e 73 70 6f 72 74 73 63 6e 2e 63 6f 6d 2f } //01 00   http://www.sportscn.com/
		$a_01_15 = {20 68 74 74 70 3a 2f 2f 77 77 77 2e 74 69 65 78 75 65 2e 6e 65 74 2f } //01 00   http://www.tiexue.net/
		$a_01_16 = {20 68 74 74 70 3a 2f 2f 77 77 77 2e 63 6d 62 63 68 69 6e 61 2e 63 6f 6d 2f } //01 00   http://www.cmbchina.com/
		$a_01_17 = {20 68 74 74 70 3a 2f 2f 77 77 77 2e 69 63 62 63 2e 63 6f 6d 2e 63 6e 2f } //01 00   http://www.icbc.com.cn/
		$a_01_18 = {20 68 74 74 70 3a 2f 2f 77 77 77 2e 6a 6f 79 6f 2e 63 6f 6d 2f } //01 00   http://www.joyo.com/
		$a_01_19 = {20 68 74 74 70 3a 2f 2f 77 77 77 2e 64 61 6e 67 64 61 6e 67 2e 63 6f 6d 2f } //01 00   http://www.dangdang.com/
		$a_01_20 = {20 68 74 74 70 3a 2f 2f 77 77 77 2e 6f 6e 6c 69 6e 65 64 6f 77 6e 2e 6e 65 74 2f } //01 00   http://www.onlinedown.net/
		$a_01_21 = {59 6f 75 54 75 62 65 20 68 74 74 70 3a 2f 2f 77 77 77 2e 79 6f 75 74 75 62 65 2e 63 6f 6d 2f } //01 00  YouTube http://www.youtube.com/
		$a_01_22 = {20 68 74 74 70 3a 2f 2f 77 77 77 2e 62 6c 69 61 6f 2e 63 6f 6d 2f } //01 00   http://www.bliao.com/
		$a_01_23 = {31 37 31 37 33 } //01 00  17173
		$a_01_24 = {20 68 74 74 70 3a 2f 2f 77 77 77 2e 31 37 31 37 33 2e 63 6f 6d 2f } //01 00   http://www.17173.com/
		$a_01_25 = {20 68 74 74 70 3a 2f 2f 77 77 77 2e 63 6d 66 75 2e 63 6f 6d 2f } //01 00   http://www.cmfu.com/
		$a_01_26 = {4d 50 33 20 68 74 74 70 3a 2f 2f 6d 70 33 2e 62 61 69 64 75 2e 63 6f 6d 2f } //05 00  MP3 http://mp3.baidu.com/
		$a_01_27 = {68 74 74 70 3a 2f 2f 77 77 77 2e 36 37 38 31 2e 63 6f 6d 2f 74 6f 6f 6c 73 2f 23 } //00 00  http://www.6781.com/tools/#
	condition:
		any of ($a_*)
 
}