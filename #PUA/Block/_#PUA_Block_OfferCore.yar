
rule _#PUA_Block_OfferCore{
	meta:
		description = "!#PUA:Block:OfferCore,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {70 61 72 74 6e 65 72 73 2d 6f 66 66 61 70 69 2e 6e 65 74 2f 61 70 69 42 75 6e 64 6c 65 } //partners-offapi.net/apiBundle  2
		$a_80_1 = {6f 66 66 65 72 69 6e 67 } //offering  1
		$a_80_2 = {59 61 6e 64 65 78 49 6e 73 74 61 6c 6c 65 72 2e 70 64 62 } //YandexInstaller.pdb  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}
rule _#PUA_Block_OfferCore_2{
	meta:
		description = "!#PUA:Block:OfferCore,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {63 6f 6e 74 72 6f 6c 2e 6b 6f 63 68 61 76 61 2e 63 6f 6d } //control.kochava.com  1
		$a_80_1 = {49 6e 73 74 61 6c 6c 6f 66 66 65 72 73 } //Installoffers  2
		$a_80_2 = {69 6e 6e 6f 73 65 74 75 70 } //innosetup  1
		$a_80_3 = {4c 69 6e 6b 76 65 72 74 69 73 65 20 47 6d 62 48 20 26 20 43 6f 2e 20 4b 47 } //Linkvertise GmbH & Co. KG  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}
rule _#PUA_Block_OfferCore_3{
	meta:
		description = "!#PUA:Block:OfferCore,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_80_0 = {64 74 2d 75 70 64 61 74 65 73 2e 63 6f 6d } //dt-updates.com  2
		$a_80_1 = {64 74 2e 77 65 62 2d 73 65 61 72 63 68 2d 68 6f 6d 65 2e 63 6f 6d } //dt.web-search-home.com  1
		$a_80_2 = {42 72 69 67 68 74 56 70 6e 4f 66 66 65 72 } //BrightVpnOffer  1
		$a_80_3 = {49 41 76 61 73 74 4f 66 66 65 72 } //IAvastOffer  1
		$a_80_4 = {44 54 57 70 66 49 6e 73 74 61 6c 6c 65 72 2e 70 64 62 } //DTWpfInstaller.pdb  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=6
 
}
rule _#PUA_Block_OfferCore_4{
	meta:
		description = "!#PUA:Block:OfferCore,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {72 61 6e 64 6f 6d 69 7a 65 2d 6f 66 66 65 72 73 } //randomize-offers  1
		$a_80_1 = {61 70 70 2d 6f 66 66 65 72 73 } //app-offers  1
		$a_80_2 = {6f 66 66 65 72 2d 65 78 69 73 74 73 } //offer-exists  1
		$a_80_3 = {6f 66 66 65 72 2d 73 68 6f 77 6e } //offer-shown  1
		$a_80_4 = {6f 66 66 65 72 73 63 72 65 65 6e 73 } //offerscreens  1
		$a_80_5 = {73 6f 66 74 70 72 65 63 64 6e 2e 72 75 } //softprecdn.ru  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}
rule _#PUA_Block_OfferCore_5{
	meta:
		description = "!#PUA:Block:OfferCore,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {2f 2f 72 69 73 65 63 6f 64 65 73 2e 63 6f 6d 2f 70 72 69 76 61 63 79 } ////risecodes.com/privacy  1
		$a_80_1 = {54 44 4f 57 4e 4c 4f 41 44 57 49 5a 41 52 44 50 41 47 45 } //TDOWNLOADWIZARDPAGE  1
		$a_80_2 = {48 49 44 45 44 4f 57 4e 4c 4f 41 44 50 41 47 45 } //HIDEDOWNLOADPAGE  1
		$a_80_3 = {4f 50 45 4e 4d 41 49 4e 43 41 52 52 49 45 52 49 4e 57 45 42 42 52 4f 57 53 45 52 } //OPENMAINCARRIERINWEBBROWSER  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}
rule _#PUA_Block_OfferCore_6{
	meta:
		description = "!#PUA:Block:OfferCore,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_80_0 = {6f 66 66 65 72 5f 73 69 7a 65 } //offer_size  1
		$a_80_1 = {79 61 6f 66 66 65 72 } //yaoffer  1
		$a_80_2 = {59 61 6e 64 65 78 50 61 63 6b 53 65 74 75 70 } //YandexPackSetup  1
		$a_80_3 = {6f 70 65 72 61 } //opera  1
		$a_80_4 = {41 76 61 73 74 53 76 63 } //AvastSvc  1
		$a_80_5 = {62 75 6e 64 6c 65 73 49 6e 73 74 61 6c 6c 65 64 } //bundlesInstalled  1
		$a_80_6 = {70 69 78 65 6c 73 65 65 2e 65 78 65 } //pixelsee.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}
rule _#PUA_Block_OfferCore_7{
	meta:
		description = "!#PUA:Block:OfferCore,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_80_0 = {41 63 63 65 70 74 } //Accept  1
		$a_80_1 = {44 65 63 6c 69 6e 65 } //Decline  1
		$a_80_2 = {4f 70 74 69 6f 6e 61 6c 20 4f 66 66 65 72 } //Optional Offer  1
		$a_80_3 = {42 75 6e 64 6c 65 4f 66 66 65 72 41 63 74 69 6f 6e } //BundleOfferAction  1
		$a_80_4 = {41 4e 20 53 6f 66 74 } //AN Soft  1
		$a_80_5 = {63 61 6d 70 61 69 67 6e 69 64 } //campaignid  1
		$a_80_6 = {53 75 72 76 65 79 } //Survey  1
		$a_80_7 = {50 72 65 6d 69 65 72 4f 70 69 6e 69 6f 6e } //PremierOpinion  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=8
 
}
rule _#PUA_Block_OfferCore_8{
	meta:
		description = "!#PUA:Block:OfferCore,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_80_0 = {64 32 75 34 64 30 38 30 63 6b 68 70 6c 68 2e 63 6c 6f 75 64 66 72 6f 6e 74 2e 6e 65 74 } //d2u4d080ckhplh.cloudfront.net  5
		$a_80_1 = {43 48 45 43 4b 4f 46 46 45 52 } //CHECKOFFER  1
		$a_80_2 = {49 4e 53 54 41 4c 4c 4f 46 46 45 52 53 } //INSTALLOFFERS  1
		$a_80_3 = {50 61 67 65 4f 66 66 65 72 41 63 74 69 76 61 74 65 } //PageOfferActivate  1
		$a_80_4 = {47 65 74 53 65 61 72 63 68 45 6e 67 69 6e 65 73 } //GetSearchEngines  1
		$a_80_5 = {63 68 65 61 74 65 6e 67 69 6e 65 } //cheatengine  5
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*5) >=12
 
}
rule _#PUA_Block_OfferCore_9{
	meta:
		description = "!#PUA:Block:OfferCore,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_81_0 = {6f 66 66 65 72 73 } //1 offers
		$a_81_1 = {4f 70 65 72 61 20 4f 6e 65 } //1 Opera One
		$a_81_2 = {49 6e 73 74 61 6c 6c 65 72 2e 70 64 62 } //1 Installer.pdb
		$a_81_3 = {44 6f 77 6e 6c 6f 61 64 20 4d 61 6e 61 67 65 72 } //1 Download Manager
		$a_81_4 = {3a 2f 2f 67 65 74 6d 79 66 69 6c 65 6e 6f 77 2e 63 6f 6d 2f 73 65 74 75 70 } //1 ://getmyfilenow.com/setup
		$a_81_5 = {55 6e 69 6e 73 74 2e 65 78 65 } //-100 Uninst.exe
		$a_81_6 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //-100 Uninstall.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*-100+(#a_81_6  & 1)*-100) >=5
 
}
rule _#PUA_Block_OfferCore_10{
	meta:
		description = "!#PUA:Block:OfferCore,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {2f 2f 72 69 73 65 63 6f 64 65 73 2e 63 6f 6d 2f 70 72 69 76 61 63 79 } ////risecodes.com/privacy  1
		$a_80_1 = {64 31 72 31 71 6f 75 32 38 63 37 63 71 67 2e 63 6c 6f 75 64 66 72 6f 6e 74 2e 6e 65 74 2f 7a 62 64 } //d1r1qou28c7cqg.cloudfront.net/zbd  1
		$a_80_2 = {47 45 54 49 4e 53 54 41 4c 4c 53 } //GETINSTALLS  1
		$a_80_3 = {44 4f 57 4e 4c 4f 41 44 54 45 4d 50 4f 52 41 52 59 46 49 4c 45 } //DOWNLOADTEMPORARYFILE  1
		$a_80_4 = {43 6f 6e 74 61 69 6e 73 4b 65 79 } //ContainsKey  1
		$a_80_5 = {41 76 69 6e 73 74 61 6c 6c 65 72 } //Avinstaller  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}
rule _#PUA_Block_OfferCore_11{
	meta:
		description = "!#PUA:Block:OfferCore,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_81_0 = {4d 65 6e 74 61 6c 4d 65 6e 74 6f 72 2e 65 78 65 } //1 MentalMentor.exe
		$a_81_1 = {53 45 54 42 55 4e 44 4c 45 4f 46 46 45 52 45 44 } //1 SETBUNDLEOFFERED
		$a_81_2 = {42 44 56 50 4e 5f 4f 4e 4c 49 4e 4b 4f 50 54 49 4f 4e 41 4c 4f 46 46 45 52 } //1 BDVPN_ONLINKOPTIONALOFFER
		$a_81_3 = {44 4f 57 4e 4c 4f 41 44 42 55 4e 44 4c 45 } //1 DOWNLOADBUNDLE
		$a_81_4 = {4c 49 4e 4b 42 52 49 47 48 54 44 41 54 41 43 4c 49 43 4b 45 44 } //1 LINKBRIGHTDATACLICKED
		$a_81_5 = {55 6e 69 6e 73 74 2e 65 78 65 } //-100 Uninst.exe
		$a_81_6 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //-100 Uninstall.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*-100+(#a_81_6  & 1)*-100) >=5
 
}
rule _#PUA_Block_OfferCore_12{
	meta:
		description = "!#PUA:Block:OfferCore,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_80_0 = {47 45 54 4f 46 46 45 52 49 4e 44 45 58 42 59 50 41 47 45 } //GETOFFERINDEXBYPAGE  1
		$a_80_1 = {49 53 54 48 45 4c 41 53 54 4f 46 46 45 52 50 41 47 45 49 46 41 4e 59 } //ISTHELASTOFFERPAGEIFANY  1
		$a_80_2 = {50 41 47 45 4f 46 46 45 52 41 43 54 49 56 41 54 45 } //PAGEOFFERACTIVATE  1
		$a_80_3 = {50 41 47 45 4f 46 46 45 52 44 45 49 4e 49 54 49 41 4c 49 5a 45 } //PAGEOFFERDEINITIALIZE  1
		$a_80_4 = {50 41 47 45 4f 46 46 45 52 43 52 45 41 54 45 } //PAGEOFFERCREATE  1
		$a_80_5 = {49 4e 53 54 41 4c 4c 4f 46 46 45 52 53 } //INSTALLOFFERS  1
		$a_80_6 = {43 48 45 43 4b 4f 46 46 45 52 } //CHECKOFFER  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}
rule _#PUA_Block_OfferCore_13{
	meta:
		description = "!#PUA:Block:OfferCore,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_80_0 = {53 6f 66 74 6f 6e 69 63 5f 44 4c 4d } //Softonic_DLM  1
		$a_80_1 = {47 45 54 41 44 53 45 52 56 45 52 52 45 53 50 4f 4e 53 45 } //GETADSERVERRESPONSE  1
		$a_80_2 = {50 41 47 45 4f 46 46 45 52 43 52 45 41 54 45 } //PAGEOFFERCREATE  1
		$a_80_3 = {50 41 47 45 4f 46 46 45 52 41 43 54 49 56 41 54 45 } //PAGEOFFERACTIVATE  1
		$a_80_4 = {47 45 54 4f 46 46 45 52 49 4e 44 45 58 42 59 50 41 47 45 } //GETOFFERINDEXBYPAGE  1
		$a_80_5 = {49 53 54 48 45 4c 41 53 54 4f 46 46 45 52 50 41 47 45 49 46 41 4e 59 } //ISTHELASTOFFERPAGEIFANY  1
		$a_80_6 = {50 41 47 45 4f 46 46 45 52 44 45 49 4e 49 54 49 41 4c 49 5a 45 } //PAGEOFFERDEINITIALIZE  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}
rule _#PUA_Block_OfferCore_14{
	meta:
		description = "!#PUA:Block:OfferCore,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_80_0 = {63 6f 6e 74 72 6f 6c 2e 6b 6f 63 68 61 76 61 2e 63 6f 6d 2f 76 31 2f 63 70 69 2f 63 6c 69 63 6b } //control.kochava.com/v1/cpi/click  1
		$a_80_1 = {64 31 70 71 6e 36 6d 35 79 77 6e 77 33 61 2e 63 6c 6f 75 64 66 72 6f 6e 74 2e 6e 65 74 } //d1pqn6m5ywnw3a.cloudfront.net  1
		$a_80_2 = {47 45 54 4f 46 46 45 52 53 41 52 52 41 59 } //GETOFFERSARRAY  1
		$a_80_3 = {50 61 67 65 4f 66 66 65 72 41 63 74 69 76 61 74 65 } //PageOfferActivate  1
		$a_80_4 = {50 41 47 45 4f 46 46 45 52 43 52 45 41 54 45 } //PAGEOFFERCREATE  1
		$a_80_5 = {59 61 6e 64 65 78 42 72 6f 77 73 65 72 } //YandexBrowser  1
		$a_80_6 = {6b 6f 68 6f 74 73 70 6f 74 2d 73 68 69 65 6c 64 } //kohotspot-shield  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}
rule _#PUA_Block_OfferCore_15{
	meta:
		description = "!#PUA:Block:OfferCore,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 09 00 00 "
		
	strings :
		$a_80_0 = {63 68 65 63 6b 5f 6f 66 66 65 72 5f 72 65 73 75 6c 74 } //check_offer_result  1
		$a_80_1 = {65 6c 69 67 69 62 6c 65 5f 6f 66 66 65 72 } //eligible_offer  1
		$a_80_2 = {6f 66 66 65 72 5f 73 65 74 } //offer_set  1
		$a_80_3 = {47 45 54 4f 46 46 45 52 49 4e 44 45 58 42 59 50 41 47 45 } //GETOFFERINDEXBYPAGE  1
		$a_80_4 = {50 41 47 45 4f 46 46 45 52 41 43 54 49 56 41 54 45 } //PAGEOFFERACTIVATE  1
		$a_80_5 = {43 52 45 41 54 45 4f 46 46 45 52 53 } //CREATEOFFERS  1
		$a_80_6 = {43 48 45 43 4b 4f 46 46 45 52 } //CHECKOFFER  1
		$a_80_7 = {50 52 4f 43 45 53 53 4f 46 46 45 52 53 54 52 49 4e 47 53 } //PROCESSOFFERSTRINGS  1
		$a_80_8 = {47 45 54 41 44 53 45 52 56 45 52 52 45 53 50 4f 4e 53 45 } //GETADSERVERRESPONSE  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1) >=7
 
}
rule _#PUA_Block_OfferCore_16{
	meta:
		description = "!#PUA:Block:OfferCore,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 09 00 00 "
		
	strings :
		$a_80_0 = {4f 66 66 65 72 49 6e 73 74 61 6c 6c 65 72 43 6f 6e 66 69 67 } //OfferInstallerConfig  1
		$a_80_1 = {4f 66 66 65 72 49 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //OfferInstaller.exe  1
		$a_80_2 = {4f 66 66 65 72 49 6e 73 74 61 6c 6c 44 61 74 61 } //OfferInstallData  1
		$a_80_3 = {4f 6e 4f 66 66 65 72 49 6e 73 74 61 6c 6c 65 64 } //OnOfferInstalled  1
		$a_80_4 = {42 75 6e 64 6c 65 49 6e 73 74 61 6c 6c 45 72 72 6f 72 } //BundleInstallError  1
		$a_80_5 = {67 65 74 5f 4f 66 66 65 72 73 } //get_Offers  1
		$a_80_6 = {4f 66 66 65 72 49 6e 73 74 61 6c 6c 65 72 2e 70 64 62 } //OfferInstaller.pdb  1
		$a_80_7 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_8 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //Uninstall.exe  -100
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*-100+(#a_80_8  & 1)*-100) >=7
 
}
rule _#PUA_Block_OfferCore_17{
	meta:
		description = "!#PUA:Block:OfferCore,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 09 00 00 "
		
	strings :
		$a_80_0 = {47 45 54 4f 46 46 45 52 49 4e 44 45 58 42 59 50 41 47 45 } //GETOFFERINDEXBYPAGE  1
		$a_80_1 = {47 45 54 4f 46 46 45 52 53 41 52 52 41 59 } //GETOFFERSARRAY  1
		$a_80_2 = {50 41 47 45 4f 46 46 45 52 41 43 54 49 56 41 54 45 } //PAGEOFFERACTIVATE  1
		$a_80_3 = {49 4e 53 54 41 4c 4c 4f 46 46 45 52 53 } //INSTALLOFFERS  1
		$a_80_4 = {43 48 45 43 4b 4f 46 46 45 52 } //CHECKOFFER  1
		$a_80_5 = {50 41 47 45 4f 46 46 45 52 42 41 43 4b 42 55 54 54 4f 4e 43 4c 49 43 4b } //PAGEOFFERBACKBUTTONCLICK  1
		$a_80_6 = {50 41 47 45 4f 46 46 45 52 53 48 4f 55 4c 44 53 4b 49 50 50 41 47 45 } //PAGEOFFERSHOULDSKIPPAGE  1
		$a_80_7 = {50 52 4f 43 45 53 53 4f 46 46 45 52 53 54 52 49 4e 47 53 } //PROCESSOFFERSTRINGS  1
		$a_80_8 = {47 45 54 41 44 53 45 52 56 45 52 52 45 53 50 4f 4e 53 45 } //GETADSERVERRESPONSE  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1) >=7
 
}
rule _#PUA_Block_OfferCore_18{
	meta:
		description = "!#PUA:Block:OfferCore,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 0b 00 00 "
		
	strings :
		$a_81_0 = {6f 70 65 6e 70 64 66 2e 65 78 65 } //1 openpdf.exe
		$a_81_1 = {50 72 6f 67 72 61 6d 73 5c 4f 70 65 72 61 5c 6f 70 65 72 61 2e 65 78 65 } //1 Programs\Opera\opera.exe
		$a_81_2 = {42 72 69 67 68 74 20 56 50 4e 5c 42 72 69 67 68 74 20 56 50 4e 2e 65 78 65 } //1 Bright VPN\Bright VPN.exe
		$a_81_3 = {33 36 30 54 6f 74 61 6c 53 65 63 75 72 69 74 79 } //1 360TotalSecurity
		$a_81_4 = {70 61 67 65 73 5f 6f 66 66 65 72 65 64 } //1 pages_offered
		$a_81_5 = {6f 66 66 65 72 65 64 } //1 offered
		$a_81_6 = {65 78 74 65 72 6e 61 6c 5f 6f 66 66 65 72 5f 73 63 72 65 65 6e } //1 external_offer_screen
		$a_81_7 = {65 78 74 65 72 6e 61 6c 5f 6f 66 66 65 72 5f 63 6f 64 65 5f 61 63 63 65 70 74 65 64 } //1 external_offer_code_accepted
		$a_81_8 = {65 78 74 65 72 6e 61 6c 5f 6f 66 66 65 72 5f 63 6f 64 65 5f 63 61 6e 63 65 6c 65 64 } //1 external_offer_code_canceled
		$a_81_9 = {55 6e 69 6e 73 74 2e 65 78 65 } //-100 Uninst.exe
		$a_81_10 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //-100 Uninstall.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*-100+(#a_81_10  & 1)*-100) >=9
 
}
rule _#PUA_Block_OfferCore_19{
	meta:
		description = "!#PUA:Block:OfferCore,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_80_0 = {53 45 54 42 55 4e 44 4c 45 4f 46 46 45 52 45 44 } //SETBUNDLEOFFERED  1
		$a_80_1 = {44 4f 57 4e 4c 4f 41 44 42 55 4e 44 4c 45 } //DOWNLOADBUNDLE  1
		$a_80_2 = {49 4e 53 54 41 4c 4c 42 55 4e 44 4c 45 } //INSTALLBUNDLE  1
		$a_80_3 = {49 4e 53 54 41 4c 4c 41 43 43 45 50 54 45 44 42 55 4e 44 4c 45 53 } //INSTALLACCEPTEDBUNDLES  1
		$a_80_4 = {4f 50 45 52 41 5f 4c 49 4e 4b 54 45 52 4d 53 43 4c 49 43 4b 45 44 } //OPERA_LINKTERMSCLICKED  1
		$a_80_5 = {4f 50 45 52 41 5f 4c 49 4e 4b 50 4f 4c 49 43 59 43 4c 49 43 4b 45 44 } //OPERA_LINKPOLICYCLICKED  1
		$a_80_6 = {43 52 45 41 54 45 4f 50 45 52 41 50 41 47 45 } //CREATEOPERAPAGE  1
		$a_80_7 = {41 56 33 36 30 5f 4c 49 4e 4b 54 45 52 4d 53 43 4c 49 43 4b 45 44 } //AV360_LINKTERMSCLICKED  1
		$a_80_8 = {41 56 33 36 30 5f 4c 49 4e 4b 50 4f 4c 49 43 59 43 4c 49 43 4b 45 44 } //AV360_LINKPOLICYCLICKED  1
		$a_80_9 = {43 52 45 41 54 45 41 56 33 36 30 50 41 47 45 } //CREATEAV360PAGE  1
		$a_80_10 = {6d 65 6e 74 61 6c 6d 65 6e 74 6f 72 2e 65 78 65 } //mentalmentor.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1) >=11
 
}
rule _#PUA_Block_OfferCore_20{
	meta:
		description = "!#PUA:Block:OfferCore,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 12 00 00 "
		
	strings :
		$a_81_0 = {41 70 70 69 6e 73 74 61 6c 6c 65 72 } //1 Appinstaller
		$a_81_1 = {41 70 70 64 61 74 65 72 } //1 Appdater
		$a_81_2 = {41 70 70 49 6e 73 74 2e 65 78 65 } //1 AppInst.exe
		$a_81_3 = {73 6f 66 74 70 72 65 63 64 6e 2e 72 75 } //1 softprecdn.ru
		$a_81_4 = {61 70 70 2d 6f 66 66 65 72 73 } //1 app-offers
		$a_81_5 = {6f 66 66 65 72 2d 65 78 69 73 74 73 } //1 offer-exists
		$a_81_6 = {6f 66 66 65 72 2d 73 68 6f 77 6e } //1 offer-shown
		$a_81_7 = {6f 66 66 65 72 2d 69 6e 73 74 61 6c 6c 69 6e 67 } //1 offer-installing
		$a_81_8 = {6f 66 66 65 72 2d 63 61 6e 63 65 6c 6c 65 64 } //1 offer-cancelled
		$a_81_9 = {6f 66 66 65 72 2d 61 62 6f 72 74 65 64 } //1 offer-aborted
		$a_81_10 = {6f 66 66 65 72 2d 61 63 74 69 76 61 74 69 6e 67 } //1 offer-activating
		$a_81_11 = {6f 66 66 65 72 2d 66 61 6c 73 65 70 6f 73 69 74 69 76 65 } //1 offer-falsepositive
		$a_81_12 = {6f 66 66 65 72 2d 69 6e 73 74 61 6c 6c 65 64 } //1 offer-installed
		$a_81_13 = {6f 66 66 65 72 2d 61 63 74 69 76 61 74 65 64 } //1 offer-activated
		$a_81_14 = {6f 66 66 65 72 2d 66 61 69 6c 65 64 } //1 offer-failed
		$a_81_15 = {6f 66 66 65 72 73 } //1 offers
		$a_81_16 = {55 6e 69 6e 73 74 2e 65 78 65 } //-100 Uninst.exe
		$a_81_17 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //-100 Uninstall.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_81_14  & 1)*1+(#a_81_15  & 1)*1+(#a_81_16  & 1)*-100+(#a_81_17  & 1)*-100) >=16
 
}
rule _#PUA_Block_OfferCore_21{
	meta:
		description = "!#PUA:Block:OfferCore,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 16 00 00 "
		
	strings :
		$a_81_0 = {41 70 70 69 6e 73 74 61 6c 6c 65 72 } //1 Appinstaller
		$a_81_1 = {61 70 70 64 61 74 65 72 } //1 appdater
		$a_81_2 = {3a 2f 2f 73 6f 66 74 70 72 65 63 64 6e 2e 72 75 2f 6f 66 66 65 72 73 63 72 65 65 6e 73 2f 61 76 61 73 74 2d 69 63 6f 6e 2e 70 6e 67 } //1 ://softprecdn.ru/offerscreens/avast-icon.png
		$a_81_3 = {3a 2f 2f 73 6f 66 74 70 72 65 63 64 6e 2e 72 75 2f 6f 66 66 65 72 73 63 72 65 65 6e 73 2f 61 76 61 73 74 2d 63 68 65 63 6b 62 6f 78 2e 70 6e 67 } //1 ://softprecdn.ru/offerscreens/avast-checkbox.png
		$a_81_4 = {3a 2f 2f 73 6f 66 74 70 72 65 63 64 6e 2e 72 75 2f 6f 66 66 65 72 73 63 72 65 65 6e 73 2f 6b 69 73 2d 69 63 6f 6e 2e 70 6e 67 } //1 ://softprecdn.ru/offerscreens/kis-icon.png
		$a_81_5 = {3a 2f 2f 73 6f 66 74 70 72 65 63 64 6e 2e 72 75 2f 6f 66 66 65 72 73 63 72 65 65 6e 73 2f 6f 6e 6c 79 5f 6f 66 66 65 72 5f 6b 69 73 5f 32 30 30 2e 70 6e 67 } //1 ://softprecdn.ru/offerscreens/only_offer_kis_200.png
		$a_81_6 = {3a 2f 2f 73 6f 66 74 70 72 65 63 64 6e 2e 72 75 2f 6f 66 66 65 72 73 63 72 65 65 6e 73 2f 6f 70 65 72 61 2d 69 63 6f 6e 2e 70 6e 67 } //1 ://softprecdn.ru/offerscreens/opera-icon.png
		$a_81_7 = {3a 2f 2f 73 6f 66 74 70 72 65 63 64 6e 2e 72 75 2f 6f 66 66 65 72 73 63 72 65 65 6e 73 2f 79 61 6e 64 65 78 2d 69 63 6f 6e 2e 70 6e 67 } //1 ://softprecdn.ru/offerscreens/yandex-icon.png
		$a_81_8 = {3a 2f 2f 73 6f 66 74 70 72 65 63 64 6e 2e 72 75 2f 6f 66 66 65 72 73 63 72 65 65 6e 73 2f 6f 6e 6c 79 5f 6f 66 66 65 72 5f 79 61 5f 32 30 30 2e 70 6e 67 } //1 ://softprecdn.ru/offerscreens/only_offer_ya_200.png
		$a_81_9 = {61 70 70 2d 6f 66 66 65 72 73 } //1 app-offers
		$a_81_10 = {6f 66 66 65 72 2d 65 78 69 73 74 73 } //1 offer-exists
		$a_81_11 = {6f 66 66 65 72 2d 73 68 6f 77 6e } //1 offer-shown
		$a_81_12 = {6f 66 66 65 72 2d 61 62 6f 72 74 65 64 } //1 offer-aborted
		$a_81_13 = {6f 66 66 65 72 2d 63 61 6e 63 65 6c 6c 65 64 } //1 offer-cancelled
		$a_81_14 = {6f 66 66 65 72 2d 69 6e 73 74 61 6c 6c 69 6e 67 } //1 offer-installing
		$a_81_15 = {6f 66 66 65 72 2d 61 63 74 69 76 61 74 69 6e 67 } //1 offer-activating
		$a_81_16 = {6f 66 66 65 72 2d 69 6e 73 74 61 6c 6c 65 64 } //1 offer-installed
		$a_81_17 = {6f 66 66 65 72 2d 61 63 74 69 76 61 74 65 64 } //1 offer-activated
		$a_81_18 = {6f 66 66 65 72 2d 66 61 69 6c 65 64 } //1 offer-failed
		$a_81_19 = {6f 66 66 65 72 73 } //1 offers
		$a_81_20 = {55 6e 69 6e 73 74 2e 65 78 65 } //-100 Uninst.exe
		$a_81_21 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //-100 Uninstall.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_81_14  & 1)*1+(#a_81_15  & 1)*1+(#a_81_16  & 1)*1+(#a_81_17  & 1)*1+(#a_81_18  & 1)*1+(#a_81_19  & 1)*1+(#a_81_20  & 1)*-100+(#a_81_21  & 1)*-100) >=20
 
}
rule _#PUA_Block_OfferCore_22{
	meta:
		description = "!#PUA:Block:OfferCore,SIGNATURE_TYPE_PEHSTR,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {54 68 65 20 57 65 62 73 68 6f 74 73 20 44 65 73 6b 74 6f 70 20 49 6e 73 74 61 6c 6c 61 74 69 6f 6e } //1 The Webshots Desktop Installation
		$a_01_1 = {49 4e 53 54 41 4c 4c 47 41 54 4f 52 } //2 INSTALLGATOR
		$a_01_2 = {66 73 67 2e 65 78 65 } //1 fsg.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=4
 
}
rule _#PUA_Block_OfferCore_23{
	meta:
		description = "!#PUA:Block:OfferCore,SIGNATURE_TYPE_PEHSTR,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {65 61 73 79 64 6f 77 6e 6c 6f 61 64 2e 65 78 65 } //1 easydownload.exe
		$a_01_1 = {42 61 62 79 6c 6f 6e 20 54 6f 6f 6c 62 61 72 } //2 Babylon Toolbar
		$a_01_2 = {3a 2f 2f 64 32 7a 30 39 35 76 65 78 62 74 66 76 69 2e 63 6c 6f 75 64 66 72 6f 6e 74 2e 6e 65 74 2f 76 66 64 2d 6f 62 2e 65 78 65 } //1 ://d2z095vexbtfvi.cloudfront.net/vfd-ob.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=4
 
}