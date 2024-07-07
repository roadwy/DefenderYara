
rule _#PUA_Block_OfferCore{
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
rule _#PUA_Block_OfferCore_2{
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
rule _#PUA_Block_OfferCore_3{
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
rule _#PUA_Block_OfferCore_4{
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
rule _#PUA_Block_OfferCore_5{
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
rule _#PUA_Block_OfferCore_6{
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
rule _#PUA_Block_OfferCore_7{
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
rule _#PUA_Block_OfferCore_8{
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
rule _#PUA_Block_OfferCore_9{
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
rule _#PUA_Block_OfferCore_10{
	meta:
		description = "!#PUA:Block:OfferCore,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 0a 00 00 "
		
	strings :
		$a_00_0 = {47 45 54 4f 46 46 45 52 53 41 52 52 41 59 } //1 GETOFFERSARRAY
		$a_00_1 = {47 45 54 49 4e 4a 45 43 54 45 44 50 41 52 41 4d } //1 GETINJECTEDPARAM
		$a_00_2 = {47 45 54 4f 46 46 45 52 49 4e 44 45 58 42 59 50 41 47 45 } //1 GETOFFERINDEXBYPAGE
		$a_00_3 = {50 41 47 45 4f 46 46 45 52 43 52 45 41 54 45 } //1 PAGEOFFERCREATE
		$a_00_4 = {50 61 67 65 4f 66 66 65 72 41 63 74 69 76 61 74 65 } //1 PageOfferActivate
		$a_80_5 = {63 61 6d 70 61 69 67 6e 5f 69 64 3d 6b 6f 68 6f 74 73 70 6f 74 2d 73 68 69 65 6c 64 } //campaign_id=kohotspot-shield  1
		$a_80_6 = {4f 70 65 72 61 5c 6f 70 65 72 61 2e 65 78 65 } //Opera\opera.exe  1
		$a_80_7 = {59 61 6e 64 65 78 5c 59 61 6e 64 65 78 42 72 6f 77 73 65 72 } //Yandex\YandexBrowser  1
		$a_80_8 = {63 6c 6f 75 64 66 72 6f 6e 74 2e 6e 65 74 2f } //cloudfront.net/  1
		$a_80_9 = {49 6e 6e 6f 53 65 74 75 70 4c 64 72 57 69 6e 64 6f 77 } //InnoSetupLdrWindow  1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1) >=9
 
}
rule _#PUA_Block_OfferCore_11{
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