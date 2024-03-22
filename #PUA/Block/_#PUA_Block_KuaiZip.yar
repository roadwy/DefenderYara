
rule _#PUA_Block_KuaiZip{
	meta:
		description = "!#PUA:Block:KuaiZip,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 03 00 "
		
	strings :
		$a_80_0 = {64 6f 77 6e 31 2e 6e 61 6e 6a 69 6e 67 63 68 65 6e 78 69 2e 63 6f 6d } //down1.nanjingchenxi.com  02 00 
		$a_80_1 = {53 6f 66 74 77 61 72 65 5c 57 68 69 72 6c 77 69 6e 64 50 64 66 } //Software\WhirlwindPdf  00 00 
	condition:
		any of ($a_*)
 
}
rule _#PUA_Block_KuaiZip_2{
	meta:
		description = "!#PUA:Block:KuaiZip,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_80_0 = {4b 75 61 69 5a 69 70 } //KuaiZip  01 00 
		$a_00_1 = {4b 75 61 69 5a 69 70 2e 4d 61 69 6e 57 6e 64 2e 54 6f 6f 6c 62 61 72 } //01 00  KuaiZip.MainWnd.Toolbar
		$a_80_2 = {57 61 69 74 4f 74 68 65 72 4b 5a 69 70 } //WaitOtherKZip  01 00 
		$a_80_3 = {4b 5a 69 70 53 68 65 6c 6c 2e 64 6c 6c } //KZipShell.dll  00 00 
	condition:
		any of ($a_*)
 
}
rule _#PUA_Block_KuaiZip_3{
	meta:
		description = "!#PUA:Block:KuaiZip,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 02 00 "
		
	strings :
		$a_80_0 = {6b 70 7a 69 70 2e 63 6f 6d } //kpzip.com  02 00 
		$a_80_1 = {4b 75 61 69 5a 69 70 20 53 65 74 75 70 } //KuaiZip Setup  01 00 
		$a_80_2 = {53 4f 46 54 57 41 52 45 5c 53 69 63 65 6e 74 } //SOFTWARE\Sicent  01 00 
		$a_80_3 = {53 4f 46 54 57 41 52 45 5c 48 69 6e 74 73 6f 66 74 } //SOFTWARE\Hintsoft  01 00 
		$a_80_4 = {53 4f 46 54 57 41 52 45 5c 47 6f 79 6f 6f } //SOFTWARE\Goyoo  00 00 
	condition:
		any of ($a_*)
 
}
rule _#PUA_Block_KuaiZip_4{
	meta:
		description = "!#PUA:Block:KuaiZip,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_80_0 = {4b 75 61 69 5a 69 70 54 69 70 73 32 } //KuaiZipTips2  01 00 
		$a_80_1 = {74 6a 2e 6b 70 7a 69 70 2e 63 6f 6d } //tj.kpzip.com  01 00 
		$a_80_2 = {68 61 6f 31 32 33 4a 75 7a 69 2e 65 78 65 } //hao123Juzi.exe  01 00 
		$a_80_3 = {61 70 69 2e 6b 70 7a 69 70 2e 63 6f 6d 2f 73 68 6f 77 63 6f 75 6e 74 2e 70 68 70 3f 6e 61 6d 65 3d } //api.kpzip.com/showcount.php?name=  01 00 
		$a_80_4 = {68 65 69 6e 6f 74 65 } //heinote  00 00 
	condition:
		any of ($a_*)
 
}
rule _#PUA_Block_KuaiZip_5{
	meta:
		description = "!#PUA:Block:KuaiZip,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_80_0 = {2f 2f 72 65 70 6f 72 74 2e 75 63 68 69 68 61 2e 6c 74 64 } ////report.uchiha.ltd  01 00 
		$a_80_1 = {64 6f 77 6e 34 2e 37 36 35 34 2e 63 6f 6d } //down4.7654.com  01 00 
		$a_80_2 = {64 2e 68 65 69 6e 6f 74 65 2e 63 6f 6d } //d.heinote.com  01 00 
		$a_80_3 = {52 65 70 6f 72 74 2e 65 78 65 } //Report.exe  01 00 
		$a_80_4 = {73 6f 66 74 77 61 72 65 5c 48 65 69 6e 6f 74 65 5c 72 65 70 6f 72 74 } //software\Heinote\report  00 00 
	condition:
		any of ($a_*)
 
}
rule _#PUA_Block_KuaiZip_6{
	meta:
		description = "!#PUA:Block:KuaiZip,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_80_0 = {6b 75 61 69 79 61 74 69 74 6c 65 } //kuaiyatitle  01 00 
		$a_80_1 = {7a 73 72 63 6b 63 67 2e 78 79 7a } //zsrckcg.xyz  01 00 
		$a_80_2 = {68 6f 74 6e 65 77 73 2e 64 66 74 6f 75 74 69 61 6f 2e 63 6f 6d } //hotnews.dftoutiao.com  01 00 
		$a_80_3 = {70 6f 70 6e 61 6d 65 3d 6d 69 6e 69 6e 65 77 73 } //popname=mininews  01 00 
		$a_80_4 = {4d 69 6e 69 44 65 62 75 67 65 72 } //MiniDebuger  01 00 
		$a_80_5 = {61 64 31 2e 37 36 35 34 2e 63 6f 6d } //ad1.7654.com  00 00 
	condition:
		any of ($a_*)
 
}
rule _#PUA_Block_KuaiZip_7{
	meta:
		description = "!#PUA:Block:KuaiZip,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_80_0 = {6b 75 61 69 7a 69 70 72 65 70 6f 72 74 2f 6d 69 6e 69 6e 65 77 73 } //kuaizipreport/mininews  01 00 
		$a_80_1 = {53 6f 66 74 77 61 72 65 5c 78 69 61 6f 79 75 5c 52 65 70 6f 72 74 5c 6f 66 66 6c 69 6e 65 } //Software\xiaoyu\Report\offline  01 00 
		$a_80_2 = {4b 5a 52 65 70 6f 72 74 2e 65 78 65 } //KZReport.exe  01 00 
		$a_80_3 = {53 65 74 50 6f 70 75 70 50 65 72 69 6f 64 } //SetPopupPeriod  01 00 
		$a_80_4 = {4d 69 6e 69 6e 65 77 73 54 69 74 6c 65 41 64 73 57 6e 64 } //MininewsTitleAdsWnd  00 00 
	condition:
		any of ($a_*)
 
}
rule _#PUA_Block_KuaiZip_8{
	meta:
		description = "!#PUA:Block:KuaiZip,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_80_0 = {4b 75 61 69 7a 69 70 } //Kuaizip  01 00 
		$a_80_1 = {2f 2f 69 2e 6b 70 7a 69 70 2e 63 6f 6d 2f 6e 2f 72 65 70 6f 72 74 2f 72 65 70 6f 72 74 2e 74 78 74 } ////i.kpzip.com/n/report/report.txt  01 00 
		$a_80_2 = {53 6f 66 74 77 61 72 65 5c 4b 75 61 69 5a 69 70 5c 49 6e 73 74 61 6c 6c } //Software\KuaiZip\Install  01 00 
		$a_80_3 = {53 6f 66 74 77 61 72 65 5c 4b 75 61 69 5a 69 70 5c 52 65 70 6f 72 74 5c 49 6e 73 74 61 6c 6c } //Software\KuaiZip\Report\Install  01 00 
		$a_80_4 = {4b 5a 52 65 70 6f 72 74 2e 65 78 65 } //KZReport.exe  00 00 
	condition:
		any of ($a_*)
 
}
rule _#PUA_Block_KuaiZip_9{
	meta:
		description = "!#PUA:Block:KuaiZip,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_80_0 = {53 6f 66 74 77 61 72 65 5c 37 36 35 34 42 72 6f 77 73 65 72 5c 55 70 64 61 74 65 43 68 65 63 6b 65 72 } //Software\7654Browser\UpdateChecker  01 00 
		$a_80_1 = {6c 6c 71 30 30 31 5c 73 72 63 5c 6f 75 74 5c 4f 66 66 69 63 69 61 6c 5c 55 70 64 61 74 65 43 68 65 63 6b 65 72 2e 65 78 65 2e 70 64 62 } //llq001\src\out\Official\UpdateChecker.exe.pdb  01 00 
		$a_80_2 = {65 72 72 2e 6c 6f 67 } //err.log  01 00 
		$a_80_3 = {7a 6d 5f 74 6f 6f 6c 73 5c 6d 75 6c 74 69 5f 65 78 65 5c 75 70 64 61 74 65 5f 63 68 65 63 6b 65 72 2e 63 63 } //zm_tools\multi_exe\update_checker.cc  00 00 
	condition:
		any of ($a_*)
 
}
rule _#PUA_Block_KuaiZip_10{
	meta:
		description = "!#PUA:Block:KuaiZip,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_80_0 = {2f 2f 64 6f 77 6e 31 2e 77 61 6c 6c 70 61 70 65 72 2e 73 68 71 69 6e 67 7a 61 6f 2e 63 6f 6d 2f 72 65 70 6f 72 74 2f 71 75 65 72 79 69 6e 66 6f 2e 78 6d 6c } ////down1.wallpaper.shqingzao.com/report/queryinfo.xml  01 00 
		$a_80_1 = {6d 69 6e 6b 65 72 6e 65 6c 5c 63 72 74 73 5c 75 63 72 74 5c 69 6e 63 5c 63 6f 72 65 63 72 74 5f 69 6e 74 65 72 6e 61 6c 5f 73 74 72 74 6f 78 2e 68 } //minkernel\crts\ucrt\inc\corecrt_internal_strtox.h  01 00 
		$a_80_2 = {52 65 70 6f 72 74 2e 65 78 65 } //Report.exe  01 00 
		$a_80_3 = {53 6f 66 74 77 61 72 65 5c 43 61 6c 66 57 61 6c 6c 70 61 70 65 72 5c 49 6e 73 74 61 6c 6c } //Software\CalfWallpaper\Install  00 00 
	condition:
		any of ($a_*)
 
}
rule _#PUA_Block_KuaiZip_11{
	meta:
		description = "!#PUA:Block:KuaiZip,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 0a 00 00 01 00 "
		
	strings :
		$a_80_0 = {6b 75 61 69 79 61 } //kuaiya  01 00 
		$a_80_1 = {6b 75 61 69 7a 69 70 } //kuaizip  01 00 
		$a_80_2 = {57 68 69 72 6c 77 69 6e 64 50 64 66 } //WhirlwindPdf  01 00 
		$a_00_3 = {32 33 34 35 63 68 72 6f 6d 65 } //01 00  2345chrome
		$a_00_4 = {74 69 70 73 2e 6e 61 6e 6a 69 6e 67 63 68 65 6e 78 69 2e 63 6f 6d } //01 00  tips.nanjingchenxi.com
		$a_00_5 = {6e 65 77 73 2e 74 6f 75 74 69 61 6f 62 61 73 68 69 2e 63 6f 6d } //01 00  news.toutiaobashi.com
		$a_00_6 = {33 36 30 63 68 72 6f 6d 65 2e 65 78 65 } //01 00  360chrome.exe
		$a_00_7 = {6f 70 65 72 61 2e 65 78 65 } //9c ff  opera.exe
		$a_80_8 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  9c ff 
		$a_80_9 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //Uninstall.exe  00 00 
	condition:
		any of ($a_*)
 
}
rule _#PUA_Block_KuaiZip_12{
	meta:
		description = "!#PUA:Block:KuaiZip,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_80_0 = {6b 75 61 69 79 61 74 69 74 6c 65 } //kuaiyatitle  01 00 
		$a_80_1 = {53 6f 66 74 77 61 72 65 5c 78 69 6e 6e 6f 74 65 5c 49 6e 73 74 61 6c 6c } //Software\xinnote\Install  01 00 
		$a_80_2 = {68 6f 74 6e 65 77 73 2e 64 66 74 6f 75 74 69 61 6f 2e 63 6f 6d } //hotnews.dftoutiao.com  01 00 
		$a_80_3 = {6e 65 77 73 2e 37 36 35 34 2e 63 6f 6d } //news.7654.com  01 00 
		$a_80_4 = {4d 69 6e 69 44 65 62 75 67 65 72 } //MiniDebuger  01 00 
		$a_02_5 = {72 00 65 00 70 00 6f 00 72 00 74 00 2e 00 90 02 0f 2e 00 6d 00 75 00 78 00 69 00 6e 00 2e 00 66 00 75 00 6e 00 90 00 } //01 00 
		$a_02_6 = {72 65 70 6f 72 74 2e 90 02 0f 2e 6d 75 78 69 6e 2e 66 75 6e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#PUA_Block_KuaiZip_13{
	meta:
		description = "!#PUA:Block:KuaiZip,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_80_0 = {69 2e 6b 70 7a 69 70 2e 63 6f 6d } //i.kpzip.com  01 00 
		$a_80_1 = {5c 4b 75 61 69 5a 69 70 5c 4b 75 61 69 5a 69 70 5f 53 65 74 75 70 2e 65 78 65 } //\KuaiZip\KuaiZip_Setup.exe  01 00 
		$a_80_2 = {61 70 69 2e 6b 70 7a 69 70 2e 63 6f 6d } //api.kpzip.com  01 00 
		$a_80_3 = {64 3a 5c 73 76 6e 72 6f 6f 74 5c 6b 75 61 69 7a 69 70 5c 74 72 75 6e 6b 5c 62 69 6e 5c 52 65 6c 65 61 73 65 5c 58 38 36 5c 4b 7a 55 70 64 61 74 65 41 67 65 6e 63 79 2e 70 64 62 } //d:\svnroot\kuaizip\trunk\bin\Release\X86\KzUpdateAgency.pdb  01 00 
		$a_80_4 = {6b 7a 75 70 64 61 74 65 61 67 65 6e 63 79 } //kzupdateagency  9c ff 
		$a_80_5 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  9c ff 
		$a_80_6 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //Uninstall.exe  00 00 
	condition:
		any of ($a_*)
 
}
rule _#PUA_Block_KuaiZip_14{
	meta:
		description = "!#PUA:Block:KuaiZip,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_80_0 = {75 73 65 5f 72 75 6e 5f 73 63 72 65 65 6e 73 61 76 65 72 5f 68 6f 74 6b 65 79 } //use_run_screensaver_hotkey  01 00 
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 53 69 63 65 6e 74 } //01 00  SOFTWARE\Sicent
		$a_80_2 = {61 64 5f 62 72 6f 77 73 65 72 5f 65 76 65 6e 74 5f 68 61 6e 64 6c 65 72 } //ad_browser_event_handler  01 00 
		$a_00_3 = {53 4f 46 54 57 41 52 45 5c 47 6f 79 6f 6f } //01 00  SOFTWARE\Goyoo
		$a_00_4 = {53 4f 46 54 57 41 52 45 5c 48 69 6e 74 73 6f 66 74 } //01 00  SOFTWARE\Hintsoft
		$a_00_5 = {52 65 6c 65 61 73 65 5f 7a 68 61 6e 5f 6d 65 6e 67 5c 57 69 6e 33 32 5c 73 63 72 65 65 6e 5f 73 61 76 65 72 2e 65 78 65 2e 70 64 62 } //01 00  Release_zhan_meng\Win32\screen_saver.exe.pdb
		$a_80_6 = {53 6f 66 74 77 61 72 65 5c 53 63 72 65 65 6e 53 61 76 65 72 } //Software\ScreenSaver  00 00 
	condition:
		any of ($a_*)
 
}
rule _#PUA_Block_KuaiZip_15{
	meta:
		description = "!#PUA:Block:KuaiZip,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_80_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 4b 75 61 69 5a 69 70 } //SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\KuaiZip  01 00 
		$a_80_1 = {53 6f 66 74 77 61 72 65 5c 4b 75 61 69 5a 69 70 5c 43 69 74 79 43 68 65 63 6b } //Software\KuaiZip\CityCheck  01 00 
		$a_80_2 = {48 65 69 6e 6f 74 65 2e 69 6e 69 } //Heinote.ini  01 00 
		$a_80_3 = {2f 2f 61 70 69 2e 6b 70 7a 69 70 2e 63 6f 6d 2f 73 68 6f 77 63 6f 75 6e 74 2e 70 68 70 3f 6e 61 6d 65 3d } ////api.kpzip.com/showcount.php?name=  01 00 
		$a_80_4 = {2f 2f 6b 79 70 6f 73 69 74 69 6f 6e 2e 64 66 74 6f 75 74 69 61 6f 2e 63 6f 6d 2f 70 6f 73 69 74 69 6f 6e 2f 67 65 74 30 32 } ////kyposition.dftoutiao.com/position/get02  00 00 
	condition:
		any of ($a_*)
 
}
rule _#PUA_Block_KuaiZip_16{
	meta:
		description = "!#PUA:Block:KuaiZip,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 09 00 00 02 00 "
		
	strings :
		$a_00_0 = {61 00 62 00 63 00 6b 00 61 00 6e 00 74 00 75 00 2e 00 63 00 6f 00 6d 00 } //02 00  abckantu.com
		$a_00_1 = {72 65 70 6f 72 74 2e 73 63 72 65 65 6e 73 61 76 65 72 73 2e 73 68 7a 68 61 6e 6d 65 6e 67 2e 63 6f 6d } //02 00  report.screensavers.shzhanmeng.com
		$a_00_2 = {64 00 6f 00 77 00 6e 00 32 00 32 00 2e 00 7a 00 6d 00 6d 00 64 00 6e 00 2e 00 63 00 6f 00 6d 00 } //01 00  down22.zmmdn.com
		$a_00_3 = {64 6f 77 6e 2e 78 69 61 6c 64 2e 63 6f 6d } //01 00  down.xiald.com
		$a_80_4 = {53 4f 46 54 57 41 52 45 5c 48 69 6e 74 73 6f 66 74 } //SOFTWARE\Hintsoft  01 00 
		$a_80_5 = {53 4f 46 54 57 41 52 45 5c 53 69 63 65 6e 74 } //SOFTWARE\Sicent  01 00 
		$a_80_6 = {53 4f 46 54 57 41 52 45 5c 47 6f 79 6f 6f } //SOFTWARE\Goyoo  02 00 
		$a_00_7 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 50 00 68 00 6f 00 74 00 6f 00 56 00 69 00 65 00 77 00 65 00 72 00 } //02 00  Software\PhotoViewer
		$a_80_8 = {53 6f 66 74 77 61 72 65 5c 53 63 72 65 65 6e 53 61 76 65 72 } //Software\ScreenSaver  00 00 
	condition:
		any of ($a_*)
 
}
rule _#PUA_Block_KuaiZip_17{
	meta:
		description = "!#PUA:Block:KuaiZip,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_80_0 = {53 6f 66 74 77 61 72 65 5c 43 61 6c 66 57 61 6c 6c 70 61 70 65 72 5c 69 6e 73 74 61 6c 6c } //Software\CalfWallpaper\install  01 00 
		$a_02_1 = {43 00 3a 00 5c 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 73 00 20 00 61 00 6e 00 64 00 20 00 53 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 5c 00 90 02 0f 5c 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 20 00 44 00 61 00 74 00 61 00 5c 00 43 00 61 00 6c 00 66 00 57 00 61 00 6c 00 6c 00 70 00 61 00 70 00 65 00 72 00 5c 00 90 00 } //01 00 
		$a_02_2 = {43 3a 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 90 02 0f 5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 43 61 6c 66 57 61 6c 6c 70 61 70 65 72 5c 90 00 } //01 00 
		$a_80_3 = {43 61 6c 66 57 61 6c 6c 70 61 70 65 72 2e 65 78 65 } //CalfWallpaper.exe  01 00 
		$a_80_4 = {67 75 61 6e 77 61 6e 67 5f 30 30 31 } //guanwang_001  01 00 
		$a_80_5 = {68 74 74 70 3a 2f 2f 72 65 70 6f 72 74 2e 77 61 6c 6c 70 61 70 65 72 2e 73 68 71 69 6e 67 7a 61 6f 2e 63 6f 6d } //http://report.wallpaper.shqingzao.com  00 00 
	condition:
		any of ($a_*)
 
}
rule _#PUA_Block_KuaiZip_18{
	meta:
		description = "!#PUA:Block:KuaiZip,SIGNATURE_TYPE_PEHSTR,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 37 36 35 34 42 72 6f 77 73 65 72 5c } //01 00  Software\7654Browser\
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4b 75 61 69 5a 69 70 5c } //01 00  Software\KuaiZip\
		$a_01_2 = {53 75 5a 69 70 } //01 00  SuZip
		$a_01_3 = {58 75 6e 5a 69 70 } //01 00  XunZip
		$a_01_4 = {6b 70 7a 69 70 2e 63 6f 6d } //01 00  kpzip.com
		$a_01_5 = {37 36 35 34 2e 63 6f 6d 2f 6e 2f 74 75 69 } //00 00  7654.com/n/tui
	condition:
		any of ($a_*)
 
}
rule _#PUA_Block_KuaiZip_19{
	meta:
		description = "!#PUA:Block:KuaiZip,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 6a 2e 67 6c 7a 69 70 2e 63 6f 6d } //01 00  tj.glzip.com
		$a_01_1 = {74 6a 31 2e 37 36 35 34 2e 63 6f 6d } //01 00  tj1.7654.com
		$a_01_2 = {78 79 6e 6f 74 65 2e 73 68 7a 68 61 6e 6d 65 6e 67 2e 63 6f 6d } //01 00  xynote.shzhanmeng.com
		$a_01_3 = {6d 69 6e 69 5f 6e 65 77 73 5f 73 6b 69 6e 5f 61 64 2e 64 6c 6c } //01 00  mini_news_skin_ad.dll
		$a_01_4 = {6b 75 61 69 7a 69 70 72 65 70 6f 72 74 } //00 00  kuaizipreport
	condition:
		any of ($a_*)
 
}
rule _#PUA_Block_KuaiZip_20{
	meta:
		description = "!#PUA:Block:KuaiZip,SIGNATURE_TYPE_PEHSTR,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {62 72 61 6e 63 68 65 73 5c 78 69 61 6f 79 75 54 72 75 6e 6b 5c 62 69 6e 5c 52 65 6c 65 61 73 65 5c 57 69 6e 33 32 5c 55 70 67 72 61 64 65 2e 70 64 62 } //01 00  branches\xiaoyuTrunk\bin\Release\Win32\Upgrade.pdb
		$a_01_1 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 78 00 69 00 61 00 6f 00 79 00 75 00 5c 00 55 00 70 00 64 00 61 00 74 00 65 00 43 00 68 00 65 00 63 00 6b 00 65 00 72 00 } //00 00  Software\xiaoyu\UpdateChecker
	condition:
		any of ($a_*)
 
}
rule _#PUA_Block_KuaiZip_21{
	meta:
		description = "!#PUA:Block:KuaiZip,SIGNATURE_TYPE_PEHSTR,07 00 07 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 6e 65 77 73 2e 37 36 35 34 2e 63 6f 6d 2f } //02 00  http://news.7654.com/
		$a_01_1 = {7b 38 38 46 36 30 30 41 43 2d 45 36 41 38 2d 34 41 45 31 2d 41 43 46 37 2d 37 33 44 35 43 41 41 44 30 39 34 33 7d } //02 00  {88F600AC-E6A8-4AE1-ACF7-73D5CAAD0943}
		$a_01_2 = {2f 73 6d 61 72 74 6c 6f 6f 6b 2f 70 6f 70 75 70 3f 63 6f 64 65 3d } //01 00  /smartlook/popup?code=
		$a_01_3 = {48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 6f 66 74 77 61 72 65 5c } //01 00  HKEY_CURRENT_USER\Software\
		$a_01_4 = {37 36 35 34 42 72 6f 77 73 65 72 } //01 00  7654Browser
		$a_01_5 = {4d 69 6e 69 4e 65 77 73 49 6e 66 6f } //00 00  MiniNewsInfo
	condition:
		any of ($a_*)
 
}
rule _#PUA_Block_KuaiZip_22{
	meta:
		description = "!#PUA:Block:KuaiZip,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 03 00 "
		
	strings :
		$a_01_0 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 53 00 69 00 63 00 65 00 6e 00 74 00 00 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 47 00 6f 00 79 00 6f 00 6f 00 00 00 00 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 48 00 69 00 6e 00 74 00 73 00 6f 00 66 00 74 00 } //01 00 
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 48 65 69 6e 6f 74 65 } //01 00  SOFTWARE\Heinote
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 78 69 61 6f 79 75 } //01 00  Software\xiaoyu
		$a_01_3 = {68 65 69 6e 6f 74 65 2e 37 36 35 34 2e 63 6f 6d 2f 78 69 65 79 69 2e 68 74 6d 6c } //01 00  heinote.7654.com/xieyi.html
		$a_01_4 = {78 69 61 6f 79 75 2e 73 68 7a 68 61 6e 6d 65 6e 67 2e 63 6f 6d 2f 6c 6f 67 6f } //00 00  xiaoyu.shzhanmeng.com/logo
	condition:
		any of ($a_*)
 
}