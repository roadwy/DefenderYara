
rule _#PUA_Block_YandexBundler{
	meta:
		description = "!#PUA:Block:YandexBundler,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {57 69 6e 52 41 52 20 76 37 2e 32 30 } //1 WinRAR v7.20
		$a_81_1 = {5c 44 6f 77 6e 6c 6f 61 64 73 5c 59 61 6e 64 65 78 46 75 6c 6c 2e 65 78 65 22 20 2d 73 69 6c 65 6e 74 } //1 \Downloads\YandexFull.exe" -silent
		$a_81_2 = {75 6e 6b 6e 6f 77 6e 64 6c 6c 2e 70 64 62 } //1 unknowndll.pdb
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}
rule _#PUA_Block_YandexBundler_2{
	meta:
		description = "!#PUA:Block:YandexBundler,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {54 65 6c 65 67 72 61 6d 20 76 36 2e 35 2e 31 } //1 Telegram v6.5.1
		$a_81_1 = {5c 44 6f 77 6e 6c 6f 61 64 73 5c 59 61 6e 64 65 78 46 75 6c 6c 2e 65 78 65 22 20 2d 73 69 6c 65 6e 74 } //1 \Downloads\YandexFull.exe" -silent
		$a_81_2 = {75 6e 6b 6e 6f 77 6e 64 6c 6c 2e 70 64 62 } //1 unknowndll.pdb
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}
rule _#PUA_Block_YandexBundler_3{
	meta:
		description = "!#PUA:Block:YandexBundler,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_81_0 = {41 7a 54 6f 72 72 65 6e 74 2e 65 78 65 } //1 AzTorrent.exe
		$a_81_1 = {5c 64 6f 77 6e 6c 6f 61 64 65 72 2e 65 78 65 20 2d 2d 70 61 72 74 6e 65 72 20 33 35 31 38 39 35 20 20 2d 2d 64 69 73 74 72 20 2f 71 75 69 65 74 20 2f 6d 73 69 63 6c } //1 \downloader.exe --partner 351895  --distr /quiet /msicl
		$a_81_2 = {42 79 20 49 6e 73 74 61 6c 6c 69 6e 67 20 59 61 6e 64 65 78 20 53 6f 66 74 77 61 72 65 20 79 6f 75 20 68 65 6c 70 20 41 7a 54 6f 72 72 65 6e 74 } //1 By Installing Yandex Software you help AzTorrent
		$a_81_3 = {59 61 6e 64 65 78 20 64 65 73 6b 74 6f 70 20 73 6f 66 74 77 61 72 65 } //1 Yandex desktop software
		$a_81_4 = {59 61 6e 64 65 78 2e 42 72 6f 77 73 65 72 } //1 Yandex.Browser
		$a_81_5 = {41 7a 54 6f 72 72 65 6e 74 20 54 6f 72 72 65 6e 74 20 46 69 6c 65 } //1 AzTorrent Torrent File
		$a_81_6 = {55 6e 69 6e 73 74 2e 65 78 65 } //-100 Uninst.exe
		$a_81_7 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //-100 Uninstall.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*-100+(#a_81_7  & 1)*-100) >=6
 
}
rule _#PUA_Block_YandexBundler_4{
	meta:
		description = "!#PUA:Block:YandexBundler,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 73 6d 69 6e 73 74 61 6c 6c 65 72 } //1 fsminstaller
		$a_01_1 = {79 61 6e 64 65 78 42 61 72 53 65 74 41 73 48 6f 6d 65 50 61 67 65 } //1 yandexBarSetAsHomePage
		$a_01_2 = {69 6e 73 74 61 6c 6c 65 72 5f 77 69 74 68 5f 79 61 6e 64 65 78 5f 62 61 72 2e 70 64 62 } //1 installer_with_yandex_bar.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}