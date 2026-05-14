
rule _#PUA_Block_Linkury{
	meta:
		description = "!#PUA:Block:Linkury,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {73 74 61 74 73 2e 68 6b 69 6a 6e 67 79 2e 6d 65 } //stats.hkijngy.me  2
		$a_80_1 = {6d 61 64 6d 61 78 2e 68 6b 69 6a 6e 67 79 2e 6d 65 } //madmax.hkijngy.me  1
		$a_80_2 = {4d 61 78 4d 69 6e 64 2e 61 73 6d 78 } //MaxMind.asmx  1
		$a_80_3 = {41 50 53 46 52 65 63 2e 65 78 65 } //APSFRec.exe  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}
rule _#PUA_Block_Linkury_2{
	meta:
		description = "!#PUA:Block:Linkury,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {74 72 61 64 65 72 73 74 72 75 74 68 72 65 76 65 61 6c 65 64 2e 63 6f 6d } //traderstruthrevealed.com  1
		$a_80_1 = {71 75 69 70 2e 65 78 65 } //quip.exe  1
		$a_80_2 = {2f 69 6d 61 67 65 73 2f 64 6f 31 35 2e 65 78 65 } ///images/do15.exe  1
		$a_80_3 = {77 69 70 65 74 2e 65 78 65 } //wipet.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}
rule _#PUA_Block_Linkury_3{
	meta:
		description = "!#PUA:Block:Linkury,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {73 74 61 74 73 2e 68 6b 69 6a 6e 67 79 2e 6d 65 } //stats.hkijngy.me  2
		$a_80_1 = {63 64 6e 2e 76 72 76 72 76 72 61 70 70 2e 63 6f 6d } //cdn.vrvrvrapp.com  1
		$a_80_2 = {53 74 61 74 69 73 74 69 63 73 53 65 72 76 69 63 65 2e 73 76 63 } //StatisticsService.svc  1
		$a_80_3 = {76 6f 74 67 75 69 2e 65 78 65 } //votgui.exe  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}
rule _#PUA_Block_Linkury_4{
	meta:
		description = "!#PUA:Block:Linkury,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {68 6b 69 6a 6e 67 79 2e 6d 65 2f 53 74 61 74 69 73 74 69 63 73 53 65 72 76 69 63 65 2e 73 76 63 } //hkijngy.me/StatisticsService.svc  2
		$a_80_1 = {6d 61 64 6d 61 78 2e 68 6b 69 6a 6e 67 79 2e 6d 65 } //madmax.hkijngy.me  1
		$a_80_2 = {73 74 61 74 73 2e 68 6b 69 6a 6e 67 79 2e 6d 65 } //stats.hkijngy.me  1
		$a_80_3 = {4e 65 74 74 72 61 6e 73 2e 65 78 65 } //Nettrans.exe  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}
rule _#PUA_Block_Linkury_5{
	meta:
		description = "!#PUA:Block:Linkury,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {73 65 61 72 63 68 2e 74 75 62 65 2d 62 61 72 2e 63 6f 6d } //search.tube-bar.com  1
		$a_80_1 = {63 6c 6f 75 64 2d 73 65 61 72 63 68 2e 6c 69 6e 6b 75 72 79 2e 63 6f 6d } //cloud-search.linkury.com  1
		$a_80_2 = {61 7a 32 39 30 30 35 35 2e 76 6f 2e 6d 73 65 63 6e 64 2e 6e 65 74 } //az290055.vo.msecnd.net  1
		$a_80_3 = {47 75 69 64 43 72 65 61 74 6f 72 2e 64 6c 6c } //GuidCreator.dll  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}
rule _#PUA_Block_Linkury_6{
	meta:
		description = "!#PUA:Block:Linkury,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_80_0 = {6c 69 6e 6b 75 72 79 2e 63 6f 6d } //linkury.com  2
		$a_80_1 = {73 66 78 72 61 72 2e 70 64 62 } //sfxrar.pdb  2
		$a_80_2 = {54 6f 6f 6c 62 61 72 57 69 6e 64 6f 77 33 32 } //ToolbarWindow32  1
		$a_80_3 = {4e 65 74 74 72 61 6e 73 2e 65 78 65 } //Nettrans.exe  1
		$a_80_4 = {73 74 61 74 73 2e 68 6b 69 6a 6e 67 79 2e 6d 65 } //stats.hkijngy.me  1
		$a_80_5 = {63 72 65 61 74 65 4e 65 77 54 61 73 6b } //createNewTask  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=7
 
}
rule _#PUA_Block_Linkury_7{
	meta:
		description = "!#PUA:Block:Linkury,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {45 78 74 65 6e 74 69 6f 6e 73 5f 69 6e 73 74 61 6c 6c 65 64 } //Extentions_installed  1
		$a_80_1 = {53 6f 66 74 77 61 72 65 5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 45 78 74 65 6e 73 69 6f 6e 73 } //Software\Google\Chrome\Extensions  1
		$a_80_2 = {73 74 61 74 73 2e 73 74 75 66 66 70 69 63 6b 73 2e 63 6f 6d } //stats.stuffpicks.com  1
		$a_80_3 = {42 61 63 6b 67 72 6f 75 6e 64 20 4c 6f 67 69 63 20 48 61 6e 64 6c 65 72 } //Background Logic Handler  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}
rule _#PUA_Block_Linkury_8{
	meta:
		description = "!#PUA:Block:Linkury,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {73 65 74 5f 4c 69 6e 6b 75 72 79 45 78 65 44 69 72 } //set_LinkuryExeDir  1
		$a_80_1 = {4c 69 6e 6b 75 72 79 49 6e 73 74 61 6c 6c 61 74 69 6f 6e 46 6f 6c 64 65 72 } //LinkuryInstallationFolder  1
		$a_80_2 = {42 61 73 69 63 4c 69 6e 6b 54 6f 4f 66 66 65 72 73 4d 61 6e 61 67 65 72 43 6c 6f 75 64 53 65 72 76 69 63 65 } //BasicLinkToOffersManagerCloudService  1
		$a_80_3 = {53 6d 61 72 74 42 61 72 4e 61 6d 65 } //SmartBarName  1
		$a_80_4 = {54 61 73 6b 62 61 72 4e 6f 74 69 66 69 65 72 45 78 65 50 61 74 68 } //TaskbarNotifierExePath  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}
rule _#PUA_Block_Linkury_9{
	meta:
		description = "!#PUA:Block:Linkury,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_80_0 = {67 65 74 5f 42 61 73 69 63 4c 69 6e 6b 54 6f 4f 66 66 65 72 73 4d 61 6e 61 67 65 72 43 6c 6f 75 64 53 65 72 76 69 63 65 } //get_BasicLinkToOffersManagerCloudService  1
		$a_80_1 = {4c 69 6e 6b 75 72 79 49 6e 73 74 61 6c 6c 61 74 69 6f 6e 46 6f 6c 64 65 72 } //LinkuryInstallationFolder  1
		$a_80_2 = {73 65 74 5f 4c 69 6e 6b 75 72 79 45 78 65 44 69 72 } //set_LinkuryExeDir  1
		$a_80_3 = {53 65 74 42 72 6f 77 73 65 72 53 65 74 74 69 6e 67 73 53 69 6c 65 6e 74 6c 79 } //SetBrowserSettingsSilently  1
		$a_80_4 = {67 65 74 5f 45 6e 63 72 79 70 74 55 52 4c } //get_EncryptURL  1
		$a_80_5 = {49 6e 74 65 72 6e 65 74 45 78 70 6c 6f 72 65 72 } //InternetExplorer  1
		$a_80_6 = {43 68 72 6f 6d 65 } //Chrome  1
		$a_80_7 = {46 69 72 65 66 6f 78 } //Firefox  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=8
 
}
rule _#PUA_Block_Linkury_10{
	meta:
		description = "!#PUA:Block:Linkury,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 0a 00 00 "
		
	strings :
		$a_80_0 = {48 6f 73 74 73 46 69 6c 65 4d 6f 6e 69 74 6f 72 4c 69 6e 6b 75 72 79 44 6f 6d 61 69 6e 73 } //HostsFileMonitorLinkuryDomains  1
		$a_80_1 = {42 75 6d 62 6c 65 42 53 74 61 74 65 53 74 61 74 69 73 74 69 63 73 45 6e 64 70 6f 69 6e 74 } //BumbleBStateStatisticsEndpoint  1
		$a_80_2 = {41 64 50 72 65 73 65 6e 74 65 72 4c 69 6e 6b } //AdPresenterLink  1
		$a_80_3 = {67 65 74 5f 49 6e 73 74 61 6c 6c 53 69 6c 65 6e 74 6c 79 } //get_InstallSilently  1
		$a_80_4 = {67 65 74 5f 42 61 73 69 63 4c 69 6e 6b 54 6f 4f 66 66 65 72 73 4d 61 6e 61 67 65 72 43 6c 6f 75 64 53 65 72 76 69 63 65 } //get_BasicLinkToOffersManagerCloudService  1
		$a_80_5 = {67 65 74 5f 54 61 73 6b 62 61 72 4e 6f 74 69 66 69 65 72 45 78 65 50 61 74 68 } //get_TaskbarNotifierExePath  1
		$a_80_6 = {67 65 74 5f 47 65 74 42 75 6e 64 6c 69 6e 67 41 70 70 6c 69 63 61 74 69 6f 6e 73 54 6f 49 6e 73 74 61 6c 6c 46 75 6e 63 74 69 6f 6e } //get_GetBundlingApplicationsToInstallFunction  1
		$a_80_7 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_8 = {55 6e 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //Uninstaller.exe  -100
		$a_80_9 = {55 6e 69 6e 73 74 61 6c 2e 65 78 65 } //Uninstal.exe  -100
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*-100+(#a_80_8  & 1)*-100+(#a_80_9  & 1)*-100) >=7
 
}