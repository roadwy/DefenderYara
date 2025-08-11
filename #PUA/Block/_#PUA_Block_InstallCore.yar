
rule _#PUA_Block_InstallCore{
	meta:
		description = "!#PUA:Block:InstallCore,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 e2 89 32 b9 ?? ?? ?? ?? 89 ca 68 ?? ?? ?? ?? 5a 31 d1 8b 31 8b d6 31 c2 89 13 81 c1 ?? ?? ?? ?? ba ?? ?? ?? ?? 03 da bf ?? ?? ?? ?? 8b d7 68 ?? ?? ?? ?? 5a 33 fa 31 cf 81 cf ?? ?? ?? ?? 0f 85 ?? ?? ?? ?? c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule _#PUA_Block_InstallCore_2{
	meta:
		description = "!#PUA:Block:InstallCore,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 c2 81 c2 ?? ?? ?? ?? ff ca 8b 4a ?? 33 cb 89 0f ba ?? ?? ?? ?? 03 c2 c7 c1 ?? ?? ?? ?? 03 f9 c7 c1 ?? ?? ?? ?? 8b d1 68 ?? ?? ?? ?? 5a 33 ca 31 c1 c7 c6 ?? ?? ?? ?? ba ?? ?? ?? ?? c1 ea ?? 31 d6 29 f1 0f 85 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule _#PUA_Block_InstallCore_3{
	meta:
		description = "!#PUA:Block:InstallCore,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {72 70 2e 44 61 64 61 66 61 72 61 64 61 2e 63 6f 6d } //rp.Dadafarada.com  2
		$a_80_1 = {53 4b 49 50 5f 4f 46 46 45 52 } //SKIP_OFFER  1
		$a_80_2 = {6f 66 66 65 72 5f 68 74 6d 6c 2e 68 74 6d 6c } //offer_html.html  1
		$a_80_3 = {77 77 77 2e 78 73 34 61 6c 6c 2e 6e 6c } //www.xs4all.nl  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}
rule _#PUA_Block_InstallCore_4{
	meta:
		description = "!#PUA:Block:InstallCore,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {49 6e 73 74 61 6c 6c 43 6f 72 65 } //InstallCore  2
		$a_80_1 = {49 6e 73 74 61 6c 6c 65 72 20 50 6f 77 65 72 65 64 20 62 79 20 69 6e 73 74 61 6c 6c 63 6f 72 65 2e 63 6f 6d } //Installer Powered by installcore.com  1
		$a_80_2 = {74 65 61 6d 40 69 6e 73 74 61 6c 6c 63 6f 72 65 2e 63 6f 6d } //team@installcore.com  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}
rule _#PUA_Block_InstallCore_5{
	meta:
		description = "!#PUA:Block:InstallCore,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {2f 2f 77 77 77 2e 78 73 34 61 6c 6c 2e 6e 6c 2f 7e 70 65 74 65 72 6e 65 64 2f } ////www.xs4all.nl/~peterned/  1
		$a_80_1 = {2f 2f 72 70 2e 54 61 64 61 6e 61 64 61 6e 65 74 2e 63 6f 6d 2f } ////rp.Tadanadanet.com/  1
		$a_80_2 = {53 50 4f 4e 53 4f 52 45 44 5f 4f 46 46 45 52 3d } //SPONSORED_OFFER=  1
		$a_80_3 = {42 55 54 54 4f 4e 5f 49 4e 53 54 41 4c 4c 3d 49 6e 73 74 61 6c 6c 20 4e 6f 77 } //BUTTON_INSTALL=Install Now  1
		$a_80_4 = {49 57 65 62 42 72 6f 77 73 65 72 } //IWebBrowser  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}
rule _#PUA_Block_InstallCore_6{
	meta:
		description = "!#PUA:Block:InstallCore,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {2f 2f 73 63 69 74 65 72 2e 63 6f 6d 2f 64 6f 63 73 2f 63 6f 6e 74 65 6e 74 2f 73 63 72 69 70 74 2f 53 74 72 65 61 6d 2e 68 74 6d } ////sciter.com/docs/content/script/Stream.htm  1
		$a_80_1 = {49 43 30 30 31 2e 52 65 73 6f 75 72 63 65 73 2e 4f 66 66 65 72 50 61 67 65 2e 68 74 6d 6c } //IC001.Resources.OfferPage.html  1
		$a_80_2 = {47 65 6e 65 72 69 63 53 65 74 75 70 2e 65 78 65 2e 63 6f 6e 66 69 67 } //GenericSetup.exe.config  1
		$a_80_3 = {49 6e 73 74 61 6c 6c 43 61 70 69 74 61 6c } //InstallCapital  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}
rule _#PUA_Block_InstallCore_7{
	meta:
		description = "!#PUA:Block:InstallCore,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {44 4f 57 4e 4c 4f 41 44 45 52 5f 4d 4f 44 45 3d 45 58 45 5f 49 4e 4a 45 43 54 45 44 5f 44 41 54 41 } //DOWNLOADER_MODE=EXE_INJECTED_DATA  1
		$a_80_1 = {69 72 73 6f 49 73 4f 70 65 72 61 49 6e 73 74 61 6c 6c 65 64 } //irsoIsOperaInstalled  1
		$a_80_2 = {49 6e 73 74 61 6c 6c 43 6f 72 65 } //InstallCore  1
		$a_80_3 = {63 68 72 6f 6d 65 2e 65 78 65 } //chrome.exe  1
		$a_80_4 = {53 6f 66 74 77 61 72 65 5c 4d 61 63 72 6f 6d 65 64 69 61 5c 46 6c 61 73 68 50 6c 61 79 65 72 } //Software\Macromedia\FlashPlayer  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}
rule _#PUA_Block_InstallCore_8{
	meta:
		description = "!#PUA:Block:InstallCore,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_80_0 = {6f 73 2e 73 65 63 75 72 65 64 64 6f 77 6e 6c 6f 61 64 63 64 6e 2e 63 6f 6d 2f 53 65 63 75 72 65 64 44 6f 77 6e 6c 6f 61 64 2f } //os.secureddownloadcdn.com/SecuredDownload/  2
		$a_80_1 = {53 48 4f 57 5f 53 50 4f 4e 53 4f 52 45 44 5f 4f 46 46 45 52 } //SHOW_SPONSORED_OFFER  1
		$a_80_2 = {53 4b 49 50 5f 4f 46 46 45 52 } //SKIP_OFFER  1
		$a_80_3 = {44 45 46 41 55 4c 54 5f 4f 46 52 5f 43 48 45 43 4b 45 52 } //DEFAULT_OFR_CHECKER  1
		$a_80_4 = {44 45 46 41 55 4c 54 5f 4f 46 52 5f 4f 4e 5f 46 49 4e 49 53 48 } //DEFAULT_OFR_ON_FINISH  1
		$a_80_5 = {4f 70 65 72 61 } //Opera  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=5
 
}
rule _#PUA_Block_InstallCore_9{
	meta:
		description = "!#PUA:Block:InstallCore,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_80_0 = {72 70 2e 63 6f 6f 6c 76 69 64 65 6f 63 6f 6e 76 65 72 74 65 72 2e 63 6f 6d } //rp.coolvideoconverter.com  1
		$a_80_1 = {63 64 6e 75 73 2e 63 6f 6f 6c 76 69 64 65 6f 63 6f 6e 76 65 72 74 65 72 2e 63 6f 6d } //cdnus.coolvideoconverter.com  1
		$a_80_2 = {53 4b 49 50 5f 4f 46 46 45 52 } //SKIP_OFFER  1
		$a_80_3 = {43 48 4f 4f 53 45 5f 44 45 46 41 55 4c 54 5f 4f 46 46 45 52 } //CHOOSE_DEFAULT_OFFER  1
		$a_80_4 = {6f 70 65 72 61 70 72 65 66 73 2e 69 6e 69 } //operaprefs.ini  1
		$a_80_5 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_6 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //Uninstall.exe  -100
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*-100+(#a_80_6  & 1)*-100) >=5
 
}
rule _#PUA_Block_InstallCore_10{
	meta:
		description = "!#PUA:Block:InstallCore,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_80_0 = {78 73 34 61 6c 6c 2e 6e 6c 2f 7e 70 65 74 65 72 6e 65 64 2f } //xs4all.nl/~peterned/  1
		$a_80_1 = {72 70 2e 62 61 69 78 61 6b 69 61 6c 74 63 64 6e 32 2e 63 6f 6d 2f } //rp.baixakialtcdn2.com/  1
		$a_80_2 = {44 45 46 41 55 4c 54 5f 4f 46 52 5f 43 4f 44 45 31 3d 64 65 66 61 75 6c 74 4f 66 66 65 72 2f 6f 66 66 65 72 5f 63 6f 64 65 2e 68 74 6d 6c } //DEFAULT_OFR_CODE1=defaultOffer/offer_code.html  1
		$a_80_3 = {49 6e 73 74 61 6c 6c 43 6f 72 65 3a 20 76 35 2e 36 36 } //InstallCore: v5.66  1
		$a_80_4 = {6f 70 65 72 61 2e 65 78 65 } //opera.exe  1
		$a_80_5 = {63 68 72 6f 6d 65 2e 65 78 65 } //chrome.exe  1
		$a_80_6 = {54 6f 6f 6c 42 61 72 } //ToolBar  1
		$a_80_7 = {54 61 73 6b 62 61 72 43 72 65 61 74 65 64 } //TaskbarCreated  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=8
 
}