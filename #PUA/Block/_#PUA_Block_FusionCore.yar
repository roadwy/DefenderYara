
rule _#PUA_Block_FusionCore{
	meta:
		description = "!#PUA:Block:FusionCore,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_80_0 = {46 75 73 69 6f 6e 2e 64 6c 6c } //Fusion.dll  2
		$a_80_1 = {42 65 64 65 64 61 66 6f } //Bededafo  1
		$a_80_2 = {48 6f 70 75 6b } //Hopuk  1
		$a_80_3 = {4d 61 6d 69 72 6f 66 65 70 69 } //Mamirofepi  1
		$a_80_4 = {4e 6f 6e 6f 6d 65 } //Nonome  1
		$a_80_5 = {50 61 73 65 6b } //Pasek  1
		$a_80_6 = {53 6f 6d 6f 70 } //Somop  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=5
 
}
rule _#PUA_Block_FusionCore_2{
	meta:
		description = "!#PUA:Block:FusionCore,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_80_0 = {46 75 73 69 6f 6e 2e 64 6c 6c } //Fusion.dll  2
		$a_80_1 = {6e 6f 78 5f 66 75 73 69 6f 6e } //nox_fusion  1
		$a_80_2 = {64 6c 34 6a 32 69 6c 34 74 64 75 33 6d 2e 63 6c 6f 75 64 66 72 6f 6e 74 2e 6e 65 74 2f 42 69 67 4e 6f 78 } //dl4j2il4tdu3m.cloudfront.net/BigNox  2
		$a_80_3 = {73 68 6f 77 20 6f 66 66 65 72 } //show offer  1
		$a_80_4 = {54 65 6d 70 5c 46 75 73 69 6f 6e 5f 6e 6f 78 } //Temp\Fusion_nox  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*2+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=4
 
}
rule _#PUA_Block_FusionCore_3{
	meta:
		description = "!#PUA:Block:FusionCore,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {64 6c 6c 3a 73 65 74 75 70 3a 66 69 6c 65 73 3a [0-0f] 2e 64 6c 6c } //1
		$a_00_1 = {64 6c 6c 3a 66 69 6c 65 73 3a 69 74 64 6f 77 6e 6c 6f 61 64 2e 64 6c 6c } //1 dll:files:itdownload.dll
		$a_00_2 = {52 55 4e 52 4b 56 45 52 49 46 59 } //1 RUNRKVERIFY
		$a_00_3 = {53 65 74 75 70 4c 64 72 2e 65 78 65 } //1 SetupLdr.exe
		$a_00_4 = {75 6e 6b 6e 6f 77 6e 64 6c 6c 2e 70 64 62 } //1 unknowndll.pdb
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
rule _#PUA_Block_FusionCore_4{
	meta:
		description = "!#PUA:Block:FusionCore,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 07 00 00 "
		
	strings :
		$a_80_0 = {66 72 65 65 20 66 75 73 69 6e 64 6c 6c 20 73 74 61 72 74 } //free fusindll start  1
		$a_80_1 = {46 55 53 5f 49 6e 69 74 44 6c 6c 20 73 74 61 72 74 } //FUS_InitDll start  1
		$a_80_2 = {66 75 6e 73 69 6f 6e 5f 64 6c 6c 5f 69 6e 69 74 65 72 72 6f 72 } //funsion_dll_initerror  1
		$a_80_3 = {72 65 63 6f 6d 6d 65 6e 64 65 64 20 66 6f 72 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 } //recommended for your computer  1
		$a_80_4 = {46 75 73 69 6f 6e 41 50 49 49 6d 70 6c 3a 3a 72 65 6c 65 61 73 65 44 4c 4c } //FusionAPIImpl::releaseDLL  1
		$a_80_5 = {6e 65 74 2f 4c 44 50 6c 61 79 65 72 5f 49 43 5f 46 53 2f 46 75 73 69 6f 6e 2e 7a 69 70 } //net/LDPlayer_IC_FS/Fusion.zip  1
		$a_80_6 = {46 75 73 69 6f 6e 41 50 49 49 6d 70 6c 20 20 73 68 6f 77 4e 65 78 74 4f 66 66 73 65 72 20 63 61 70 20 25 73 2c 20 64 65 73 63 20 25 73 } //FusionAPIImpl  showNextOffser cap %s, desc %s  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=3
 
}
rule _#PUA_Block_FusionCore_5{
	meta:
		description = "!#PUA:Block:FusionCore,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 0a 00 00 "
		
	strings :
		$a_01_0 = {46 55 53 49 4f 4e 49 4e 49 54 49 41 4c 49 5a 45 49 4e 49 54 } //1 FUSIONINITIALIZEINIT
		$a_01_1 = {46 55 53 49 4f 4e 49 4e 49 54 49 41 4c 49 5a 45 57 49 5a 41 52 44 } //1 FUSIONINITIALIZEWIZARD
		$a_01_2 = {46 55 53 49 4f 4e 53 48 4f 55 4c 44 53 4b 49 50 50 41 47 45 } //1 FUSIONSHOULDSKIPPAGE
		$a_01_3 = {46 55 53 49 4f 4e 43 55 52 50 41 47 45 43 48 41 4e 47 45 44 } //1 FUSIONCURPAGECHANGED
		$a_01_4 = {46 55 53 49 4f 4e 44 45 49 4e 49 54 49 41 4c 49 5a 45 53 45 54 55 50 } //1 FUSIONDEINITIALIZESETUP
		$a_01_5 = {46 55 53 49 4f 4e 53 45 54 4f 46 46 45 52 53 50 41 47 45 42 41 43 4b 47 52 4f 55 4e 44 } //1 FUSIONSETOFFERSPAGEBACKGROUND
		$a_01_6 = {46 55 53 49 4f 4e 57 41 49 54 46 4f 52 4f 46 46 45 52 } //1 FUSIONWAITFOROFFER
		$a_01_7 = {46 55 53 49 4f 4e 52 45 50 4f 52 54 49 4e 53 54 41 4c 4c 41 54 49 4f 4e 45 52 52 4f 52 } //1 FUSIONREPORTINSTALLATIONERROR
		$a_01_8 = {46 55 53 49 4f 4e 47 45 54 4f 46 46 45 52 53 50 52 4f 47 52 45 53 53 } //1 FUSIONGETOFFERSPROGRESS
		$a_00_9 = {52 65 63 6f 6d 6d 65 6e 64 65 64 20 66 6f 72 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 } //1 Recommended for your computer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_00_9  & 1)*1) >=3
 
}
rule _#PUA_Block_FusionCore_6{
	meta:
		description = "!#PUA:Block:FusionCore,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {46 75 73 69 6f 6e 2e 64 6c 6c } //2 Fusion.dll
		$a_01_1 = {46 55 53 5f 53 48 4f 57 4f 46 46 45 52 53 } //2 FUS_SHOWOFFERS
		$a_01_2 = {46 55 53 5f 4e 45 58 54 4f 46 46 45 52 } //2 FUS_NEXTOFFER
		$a_01_3 = {46 55 53 5f 49 4e 53 54 41 4c 4c 4f 46 46 45 52 53 } //2 FUS_INSTALLOFFERS
		$a_01_4 = {46 55 53 5f 53 45 54 4d 41 49 4e 50 52 4f 44 55 43 54 53 54 41 54 55 53 } //2 FUS_SETMAINPRODUCTSTATUS
		$a_01_5 = {46 55 53 5f 57 41 49 54 41 4e 44 46 52 45 45 44 4c 4c } //2 FUS_WAITANDFREEDLL
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=6
 
}
rule _#PUA_Block_FusionCore_7{
	meta:
		description = "!#PUA:Block:FusionCore,SIGNATURE_TYPE_PEHSTR,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_01_0 = {46 75 73 69 6f 6e 2e 64 6c 6c } //1 Fusion.dll
		$a_01_1 = {46 72 65 65 4f 66 66 65 72 73 } //1 FreeOffers
		$a_01_2 = {47 65 74 4f 66 66 65 72 73 50 72 6f 67 72 65 73 73 } //1 GetOffersProgress
		$a_01_3 = {47 65 74 4f 66 66 65 72 73 53 74 61 74 75 73 } //1 GetOffersStatus
		$a_01_4 = {48 65 6c 70 65 72 48 69 64 65 49 63 6f 6e } //1 HelperHideIcon
		$a_01_5 = {48 65 6c 70 65 72 53 79 6e 63 54 68 72 65 61 64 } //1 HelperSyncThread
		$a_01_6 = {49 6e 69 74 4f 66 66 65 72 73 } //1 InitOffers
		$a_01_7 = {49 6e 73 74 61 6c 6c 4f 66 66 65 72 73 } //1 InstallOffers
		$a_01_8 = {49 73 4c 6f 61 64 65 64 } //1 IsLoaded
		$a_01_9 = {4e 65 78 74 4f 66 66 65 72 } //1 NextOffer
		$a_01_10 = {53 65 74 4d 61 69 6e 50 72 6f 64 75 63 74 53 74 61 74 75 73 } //1 SetMainProductStatus
		$a_01_11 = {53 65 74 4f 66 66 65 72 73 57 69 6e 64 6f 77 } //1 SetOffersWindow
		$a_01_12 = {53 68 6f 77 4f 66 66 65 72 73 } //1 ShowOffers
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=13
 
}
rule _#PUA_Block_FusionCore_8{
	meta:
		description = "!#PUA:Block:FusionCore,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {46 75 73 69 6f 6e 2e 64 6c 6c } //1 Fusion.dll
		$a_01_1 = {46 55 53 5f 47 65 74 4f 66 66 65 72 43 61 70 74 69 6f 6e 41 } //1 FUS_GetOfferCaptionA
		$a_01_2 = {46 55 53 5f 47 65 74 4f 66 66 65 72 73 50 72 6f 67 72 65 73 73 } //1 FUS_GetOffersProgress
		$a_01_3 = {46 55 53 5f 48 69 64 65 4f 66 66 65 72 73 } //1 FUS_HideOffers
		$a_01_4 = {46 55 53 5f 49 6e 73 74 61 6c 6c 4f 66 66 65 72 73 } //1 FUS_InstallOffers
		$a_01_5 = {46 55 53 5f 4e 65 78 74 4f 66 66 65 72 } //1 FUS_NextOffer
		$a_01_6 = {46 55 53 5f 53 65 74 4d 61 69 6e 50 72 6f 64 75 63 74 53 74 61 74 75 73 } //1 FUS_SetMainProductStatus
		$a_01_7 = {46 55 53 5f 53 65 74 4f 66 66 65 72 73 57 69 6e 64 6f 77 } //1 FUS_SetOffersWindow
		$a_01_8 = {46 55 53 5f 53 68 6f 77 4f 66 66 65 72 73 } //1 FUS_ShowOffers
		$a_01_9 = {46 55 53 5f 57 61 69 74 41 6e 64 46 72 65 65 44 6c 6c } //1 FUS_WaitAndFreeDll
		$a_01_10 = {46 55 53 5f 57 61 69 74 46 6f 72 4f 66 66 65 72 73 54 6f 42 65 52 65 61 64 79 } //1 FUS_WaitForOffersToBeReady
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}
rule _#PUA_Block_FusionCore_9{
	meta:
		description = "!#PUA:Block:FusionCore,SIGNATURE_TYPE_PEHSTR,07 00 07 00 08 00 00 "
		
	strings :
		$a_01_0 = {46 00 75 00 73 00 69 00 6f 00 6e 00 2e 00 64 00 6c 00 6c 00 } //2 Fusion.dll
		$a_01_1 = {5c 00 54 00 65 00 6d 00 70 00 5c 00 46 00 75 00 73 00 69 00 6f 00 6e 00 5f 00 6c 00 64 00 5c 00 } //2 \Temp\Fusion_ld\
		$a_01_2 = {73 00 68 00 6f 00 77 00 4f 00 66 00 66 00 65 00 72 00 20 00 65 00 6e 00 64 00 } //2 showOffer end
		$a_01_3 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 5f 00 61 00 63 00 63 00 65 00 70 00 74 00 4f 00 66 00 66 00 65 00 72 00 } //1 download_acceptOffer
		$a_01_4 = {5a 00 68 00 69 00 5c 00 4c 00 44 00 50 00 6c 00 61 00 79 00 65 00 72 00 } //1 Zhi\LDPlayer
		$a_01_5 = {5c 64 6f 77 6e 6c 6f 61 64 65 72 5c 62 69 6e 5c 6c 64 70 6c 61 79 65 72 69 6e 73 74 2e 70 64 62 } //1 \downloader\bin\ldplayerinst.pdb
		$a_01_6 = {64 32 6a 61 6e 6c 74 6e 69 63 76 37 75 68 2e 63 6c 6f 75 64 66 72 6f 6e 74 2e 6e 65 74 2f 4c 44 50 6c 61 79 65 72 } //5 d2janltnicv7uh.cloudfront.net/LDPlayer
		$a_01_7 = {57 69 6e 41 70 69 44 65 63 72 79 70 74 46 69 6c 65 46 75 73 69 6f 6e } //2 WinApiDecryptFileFusion
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*5+(#a_01_7  & 1)*2) >=7
 
}