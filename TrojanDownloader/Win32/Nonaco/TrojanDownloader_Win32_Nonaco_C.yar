
rule TrojanDownloader_Win32_Nonaco_C{
	meta:
		description = "TrojanDownloader:Win32/Nonaco.C,SIGNATURE_TYPE_PEHSTR,ffffff8e 03 ffffff84 03 12 00 00 "
		
	strings :
		$a_01_0 = {30 31 32 33 34 35 36 37 38 39 41 42 43 44 45 46 } //100 0123456789ABCDEF
		$a_01_1 = {39 39 39 39 2d 39 39 2d 39 39 } //100 9999-99-99
		$a_01_2 = {43 6c 69 63 6b 54 69 6d 65 } //100 ClickTime
		$a_01_3 = {46 65 65 64 55 72 6c } //100 FeedUrl
		$a_01_4 = {49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 } //100 Internet Explorer
		$a_01_5 = {49 6e 74 65 72 6e 65 74 43 68 65 63 6b 43 6f 6e 6e 65 63 74 69 6f 6e 41 } //100 InternetCheckConnectionA
		$a_01_6 = {4d 69 63 72 6f 73 6f 66 74 5c } //100 Microsoft\
		$a_01_7 = {53 4f 46 54 57 41 52 45 5c } //50 SOFTWARE\
		$a_01_8 = {54 6f 46 65 65 64 } //50 ToFeed
		$a_01_9 = {55 70 64 61 74 65 55 72 6c } //50 UpdateUrl
		$a_01_10 = {25 73 3f 70 69 64 3d 25 30 34 64 26 64 74 3d 25 73 } //50 %s?pid=%04d&dt=%s
		$a_01_11 = {68 74 74 70 3a 2f 2f 7a 65 72 6f 2e 61 6c 6c 67 72 65 61 74 68 6f 73 74 2e 63 6f 6d } //10 http://zero.allgreathost.com
		$a_01_12 = {68 74 74 70 3a 2f 2f 7a 65 72 6f 2e 73 69 73 64 6f 74 6e 65 74 2e 63 6f 6d } //10 http://zero.sisdotnet.com
		$a_01_13 = {68 74 74 70 3a 2f 2f 7a 65 72 6f 2e 62 65 73 74 6d 61 6e 61 67 65 31 2e 6f 72 67 } //10 http://zero.bestmanage1.org
		$a_01_14 = {68 74 74 70 3a 2f 2f 7a 65 72 6f 2e 62 65 73 74 6d 61 6e 61 67 65 32 2e 6f 72 67 } //10 http://zero.bestmanage2.org
		$a_01_15 = {68 74 74 70 3a 2f 2f 7a 65 72 6f 2e 62 65 73 74 6d 61 6e 61 67 65 33 2e 6f 72 67 } //10 http://zero.bestmanage3.org
		$a_01_16 = {68 74 74 70 3a 2f 2f 7a 65 72 6f 2e 78 75 6a 61 63 65 2e 63 6f 6d } //10 http://zero.xujace.com
		$a_01_17 = {68 74 74 70 3a 2f 2f 73 65 74 75 70 2e 74 68 65 6f 72 65 6f 6e 2e 63 6f 6d } //10 http://setup.theoreon.com
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100+(#a_01_3  & 1)*100+(#a_01_4  & 1)*100+(#a_01_5  & 1)*100+(#a_01_6  & 1)*100+(#a_01_7  & 1)*50+(#a_01_8  & 1)*50+(#a_01_9  & 1)*50+(#a_01_10  & 1)*50+(#a_01_11  & 1)*10+(#a_01_12  & 1)*10+(#a_01_13  & 1)*10+(#a_01_14  & 1)*10+(#a_01_15  & 1)*10+(#a_01_16  & 1)*10+(#a_01_17  & 1)*10) >=900
 
}