
rule _#PUA_Block_InstallCore{
	meta:
		description = "!#PUA:Block:InstallCore,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {89 e2 89 32 b9 90 01 04 89 ca 68 90 01 04 5a 31 d1 8b 31 8b d6 31 c2 89 13 81 c1 90 01 04 ba 90 01 04 03 da bf 90 01 04 8b d7 68 90 01 04 5a 33 fa 31 cf 81 cf 90 01 04 0f 85 90 01 04 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#PUA_Block_InstallCore_2{
	meta:
		description = "!#PUA:Block:InstallCore,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {89 c2 81 c2 90 01 04 ff ca 8b 4a 90 01 01 33 cb 89 0f ba 90 01 04 03 c2 c7 c1 90 01 04 03 f9 c7 c1 90 01 04 8b d1 68 90 01 04 5a 33 ca 31 c1 c7 c6 90 01 04 ba 90 01 04 c1 ea 90 01 01 31 d6 29 f1 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#PUA_Block_InstallCore_3{
	meta:
		description = "!#PUA:Block:InstallCore,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_80_0 = {2f 2f 77 77 77 2e 78 73 34 61 6c 6c 2e 6e 6c 2f 7e 70 65 74 65 72 6e 65 64 2f } ////www.xs4all.nl/~peterned/  01 00 
		$a_80_1 = {2f 2f 72 70 2e 54 61 64 61 6e 61 64 61 6e 65 74 2e 63 6f 6d 2f } ////rp.Tadanadanet.com/  01 00 
		$a_80_2 = {53 50 4f 4e 53 4f 52 45 44 5f 4f 46 46 45 52 3d } //SPONSORED_OFFER=  01 00 
		$a_80_3 = {42 55 54 54 4f 4e 5f 49 4e 53 54 41 4c 4c 3d 49 6e 73 74 61 6c 6c 20 4e 6f 77 } //BUTTON_INSTALL=Install Now  01 00 
		$a_80_4 = {49 57 65 62 42 72 6f 77 73 65 72 } //IWebBrowser  00 00 
	condition:
		any of ($a_*)
 
}
rule _#PUA_Block_InstallCore_4{
	meta:
		description = "!#PUA:Block:InstallCore,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_80_0 = {2f 2f 73 63 69 74 65 72 2e 63 6f 6d 2f 64 6f 63 73 2f 63 6f 6e 74 65 6e 74 2f 73 63 72 69 70 74 2f 53 74 72 65 61 6d 2e 68 74 6d } ////sciter.com/docs/content/script/Stream.htm  01 00 
		$a_80_1 = {49 43 30 30 31 2e 52 65 73 6f 75 72 63 65 73 2e 4f 66 66 65 72 50 61 67 65 2e 68 74 6d 6c } //IC001.Resources.OfferPage.html  01 00 
		$a_80_2 = {47 65 6e 65 72 69 63 53 65 74 75 70 2e 65 78 65 2e 63 6f 6e 66 69 67 } //GenericSetup.exe.config  01 00 
		$a_80_3 = {49 6e 73 74 61 6c 6c 43 61 70 69 74 61 6c } //InstallCapital  00 00 
	condition:
		any of ($a_*)
 
}
rule _#PUA_Block_InstallCore_5{
	meta:
		description = "!#PUA:Block:InstallCore,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_80_0 = {72 70 2e 63 6f 6f 6c 76 69 64 65 6f 63 6f 6e 76 65 72 74 65 72 2e 63 6f 6d } //rp.coolvideoconverter.com  01 00 
		$a_80_1 = {63 64 6e 75 73 2e 63 6f 6f 6c 76 69 64 65 6f 63 6f 6e 76 65 72 74 65 72 2e 63 6f 6d } //cdnus.coolvideoconverter.com  01 00 
		$a_80_2 = {53 4b 49 50 5f 4f 46 46 45 52 } //SKIP_OFFER  01 00 
		$a_80_3 = {43 48 4f 4f 53 45 5f 44 45 46 41 55 4c 54 5f 4f 46 46 45 52 } //CHOOSE_DEFAULT_OFFER  01 00 
		$a_80_4 = {6f 70 65 72 61 70 72 65 66 73 2e 69 6e 69 } //operaprefs.ini  9c ff 
		$a_80_5 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  9c ff 
		$a_80_6 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //Uninstall.exe  00 00 
	condition:
		any of ($a_*)
 
}