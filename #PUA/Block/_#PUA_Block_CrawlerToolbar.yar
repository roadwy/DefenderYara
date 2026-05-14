
rule _#PUA_Block_CrawlerToolbar{
	meta:
		description = "!#PUA:Block:CrawlerToolbar,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 54 6f 6f 6c 62 61 72 2e 65 78 65 } //1 CToolbar.exe
		$a_01_1 = {43 72 61 77 6c 65 72 54 6f 6f 6c 62 61 72 } //1 CrawlerToolbar
		$a_00_2 = {43 00 72 00 61 00 77 00 6c 00 65 00 72 00 2e 00 63 00 6f 00 6d 00 } //1 Crawler.com
		$a_01_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 79 6f 75 73 65 6e 64 69 74 2e 63 6f 6d 2f } //1 http://www.yousendit.com/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule _#PUA_Block_CrawlerToolbar_2{
	meta:
		description = "!#PUA:Block:CrawlerToolbar,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_80_0 = {77 77 77 2e 32 34 78 37 68 65 6c 70 2e 6f 72 67 } //www.24x7help.org  2
		$a_80_1 = {77 77 77 2e 77 65 62 73 65 61 72 63 68 2e 63 6f 6d } //www.websearch.com  1
		$a_80_2 = {64 6e 6c 2e 61 70 70 67 72 61 66 66 69 74 69 2e 63 6f 6d } //dnl.appgraffiti.com  1
		$a_80_3 = {57 65 62 53 65 61 72 63 68 2e 65 78 65 } //WebSearch.exe  1
		$a_80_4 = {54 6f 6f 6c 62 61 72 } //Toolbar  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=6
 
}
rule _#PUA_Block_CrawlerToolbar_3{
	meta:
		description = "!#PUA:Block:CrawlerToolbar,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_80_0 = {64 6e 6c 2e 61 70 70 67 72 61 66 66 69 74 69 2e 63 6f 6d } //dnl.appgraffiti.com  2
		$a_80_1 = {41 70 70 47 72 61 66 66 69 74 69 53 65 74 75 70 2e 65 78 65 } //AppGraffitiSetup.exe  1
		$a_80_2 = {64 6f 77 6e 6c 6f 61 64 2e 72 65 62 61 74 65 62 6c 61 73 74 2e 63 6f 6d } //download.rebateblast.com  1
		$a_80_3 = {52 65 62 61 74 65 49 6e 66 6f 72 6d 65 72 53 65 74 75 70 2e 65 78 65 } //RebateInformerSetup.exe  1
		$a_80_4 = {54 52 49 41 4c 20 4f 46 46 45 52 53 } //TRIAL OFFERS  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=6
 
}
rule _#PUA_Block_CrawlerToolbar_4{
	meta:
		description = "!#PUA:Block:CrawlerToolbar,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {77 77 77 2e 63 72 61 77 6c 65 72 2e 63 6f 6d } //1 www.crawler.com
		$a_01_1 = {25 69 63 6f 64 65 25 26 73 44 61 74 65 3d 25 69 64 61 74 65 25 26 73 54 69 6d 65 3d 25 69 74 69 6d 65 25 26 73 4c 50 3d 25 4c 50 63 6f 6f 6b 69 65 25 } //1 %icode%&sDate=%idate%&sTime=%itime%&sLP=%LPcookie%
		$a_01_2 = {4b 6f 6c 43 6c 61 73 73 65 73 5f 44 65 76 } //1 KolClasses_Dev
		$a_01_3 = {25 42 52 41 4e 44 20 54 6f 6f 6c 62 61 72 20 53 65 72 76 65 72 20 41 70 70 6c 69 63 61 74 69 6f 6e } //1 %BRAND Toolbar Server Application
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule _#PUA_Block_CrawlerToolbar_5{
	meta:
		description = "!#PUA:Block:CrawlerToolbar,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_81_0 = {43 72 61 77 6c 65 72 20 47 72 6f 75 70 } //1 Crawler Group
		$a_81_1 = {53 70 79 77 61 72 65 20 54 65 72 6d 69 6e 61 74 6f 72 20 32 30 31 35 } //1 Spyware Terminator 2015
		$a_81_2 = {53 70 79 77 61 72 65 54 65 72 6d 69 6e 61 74 6f 72 2e 65 78 65 } //1 SpywareTerminator.exe
		$a_81_3 = {49 6e 62 6f 78 20 53 74 6f 72 61 67 65 } //1 Inbox Storage
		$a_81_4 = {3a 2f 2f 73 74 6f 72 61 67 65 2e 69 6e 62 6f 78 2e 63 6f 6d 2f 64 6e 6c 2f 63 6f 6e 66 69 67 2f 32 32 2f 49 53 53 65 74 75 70 2e 65 78 65 } //1 ://storage.inbox.com/dnl/config/22/ISSetup.exe
		$a_81_5 = {3a 2f 2f 77 77 77 2e 6d 79 6c 6f 67 6f 6e 2e 63 6f 6d 2f 64 6e 6c 2f 63 6f 6e 66 69 67 2f 32 32 2f 4d 79 4c 6f 67 6f 6e 4d 61 6e 61 67 65 72 53 65 74 75 70 2e 65 78 65 } //1 ://www.mylogon.com/dnl/config/22/MyLogonManagerSetup.exe
		$a_81_6 = {55 6e 69 6e 73 74 2e 65 78 65 } //-100 Uninst.exe
		$a_81_7 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //-100 Uninstall.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*-100+(#a_81_7  & 1)*-100) >=6
 
}