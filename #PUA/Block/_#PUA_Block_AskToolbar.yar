
rule _#PUA_Block_AskToolbar{
	meta:
		description = "!#PUA:Block:AskToolbar,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {70 69 70 6f 66 66 65 72 73 2e 61 70 6e 70 61 72 74 6e 65 72 73 2e 63 6f 6d } //pipoffers.apnpartners.com  2
		$a_80_1 = {44 69 73 70 6c 61 79 4f 66 66 65 72 } //DisplayOffer  1
		$a_80_2 = {6f 66 66 65 72 65 75 6c 61 } //offereula  1
		$a_80_3 = {41 73 6b 54 6f 6f 6c 62 61 72 } //AskToolbar  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}
rule _#PUA_Block_AskToolbar_2{
	meta:
		description = "!#PUA:Block:AskToolbar,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_00_0 = {61 70 6e 73 74 61 74 69 63 2e 61 73 6b 2e 63 6f 6d } //2 apnstatic.ask.com
		$a_00_1 = {6f 66 66 65 72 6c 69 73 74 } //1 offerlist
		$a_00_2 = {4f 66 66 65 72 43 61 73 74 } //1 OfferCast
		$a_00_3 = {4f 43 50 61 63 6b 65 72 2e 70 64 62 } //1 OCPacker.pdb
		$a_80_4 = {41 50 4e 49 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //APNInstaller.exe  1
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_80_4  & 1)*1) >=6
 
}
rule _#PUA_Block_AskToolbar_3{
	meta:
		description = "!#PUA:Block:AskToolbar,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {41 73 6b 20 54 6f 6f 6c 62 61 72 2e 6d 73 69 } //Ask Toolbar.msi  2
		$a_80_1 = {77 65 62 73 65 61 72 63 68 2e 61 73 6b 2e 63 6f 6d } //websearch.ask.com  1
		$a_80_2 = {47 65 6e 65 72 69 63 41 73 6b 54 6f 6f 6c 62 61 72 2e 64 6c 6c } //GenericAskToolbar.dll  1
		$a_80_3 = {65 78 74 65 72 6e 61 6c 77 72 61 70 70 65 72 2e 70 64 62 } //externalwrapper.pdb  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}
rule _#PUA_Block_AskToolbar_4{
	meta:
		description = "!#PUA:Block:AskToolbar,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {43 3a 5c 4a 65 6e 6b 69 6e 73 5c 77 6f 72 6b 73 70 61 63 65 5c 4f 43 33 2e 58 5c 4f 43 5c 52 65 6c 65 61 73 65 5c 4f 43 50 61 63 6b 65 72 2e 70 64 62 } //C:\Jenkins\workspace\OC3.X\OC\Release\OCPacker.pdb  1
		$a_80_1 = {4f 66 66 65 72 63 61 73 74 } //Offercast  1
		$a_80_2 = {6f 66 66 65 72 6c 69 73 74 2e 6a 73 } //offerlist.js  1
		$a_80_3 = {41 73 6b 2e 63 6f 6d } //Ask.com  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}
rule _#PUA_Block_AskToolbar_5{
	meta:
		description = "!#PUA:Block:AskToolbar,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_81_0 = {50 6c 61 79 46 69 7a 7a 20 49 6e 73 74 61 6c 6c 65 72 } //1 PlayFizz Installer
		$a_81_1 = {49 6e 73 74 61 6c 6c 69 6e 67 20 43 6f 6e 64 75 69 74 20 74 6f 6f 6c 62 61 72 } //1 Installing Conduit toolbar
		$a_81_2 = {41 73 6b 20 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 20 66 69 6e 69 73 68 65 64 } //1 Ask installation finished
		$a_81_3 = {55 6e 69 6e 73 74 2e 65 78 65 } //-100 Uninst.exe
		$a_81_4 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //-100 Uninstall.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*-100+(#a_81_4  & 1)*-100) >=3
 
}
rule _#PUA_Block_AskToolbar_6{
	meta:
		description = "!#PUA:Block:AskToolbar,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_81_0 = {53 65 74 75 70 20 2d 20 43 75 74 65 50 44 46 20 57 72 69 74 65 72 } //1 Setup - CutePDF Writer
		$a_81_1 = {41 73 6b 20 54 6f 6f 6c 62 61 72 } //1 Ask Toolbar
		$a_81_2 = {74 6f 6f 6c 62 61 72 } //1 toolbar
		$a_81_3 = {6f 66 66 65 72 65 75 6c 61 } //1 offereula
		$a_81_4 = {41 73 6b 49 6e 73 74 61 6c 6c 65 72 } //1 AskInstaller
		$a_81_5 = {55 6e 69 6e 73 74 2e 65 78 65 } //-100 Uninst.exe
		$a_81_6 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //-100 Uninstall.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*-100+(#a_81_6  & 1)*-100) >=5
 
}
rule _#PUA_Block_AskToolbar_7{
	meta:
		description = "!#PUA:Block:AskToolbar,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_81_0 = {45 78 61 63 74 20 41 75 64 69 6f 20 43 6f 70 79 } //1 Exact Audio Copy
		$a_81_1 = {45 78 61 63 74 20 41 75 64 69 6f 20 43 6f 70 79 2e 6c 6e 6b } //1 Exact Audio Copy.lnk
		$a_81_2 = {45 41 43 2e 65 78 65 } //1 EAC.exe
		$a_81_3 = {61 73 6b 54 6f 6f 6c 62 61 72 49 6e 73 74 61 6c 6c 65 72 2d 31 2e 37 2e 30 2e 30 2e 65 78 65 } //1 askToolbarInstaller-1.7.0.0.exe
		$a_81_4 = {41 73 6b 54 6f 6f 6c 62 61 72 32 2e 62 6d 70 } //1 AskToolbar2.bmp
		$a_81_5 = {55 6e 69 6e 73 74 2e 65 78 65 } //-100 Uninst.exe
		$a_81_6 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //-100 Uninstall.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*-100+(#a_81_6  & 1)*-100) >=5
 
}
rule _#PUA_Block_AskToolbar_8{
	meta:
		description = "!#PUA:Block:AskToolbar,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_81_0 = {65 6d 62 65 64 6f 66 66 65 72 32 78 74 65 6d 70 6c 61 74 65 2e 68 74 6d 55 54 } //1 embedoffer2xtemplate.htmUT
		$a_81_1 = {6f 66 66 65 72 32 78 74 65 6d 70 6c 61 74 65 2e 68 74 6d 55 54 } //1 offer2xtemplate.htmUT
		$a_81_2 = {6f 66 66 65 72 6c 69 73 74 2e 6a 73 55 54 } //1 offerlist.jsUT
		$a_81_3 = {41 50 4e 49 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //1 APNInstaller.exe
		$a_81_4 = {4f 66 66 65 72 63 61 73 74 20 2d 20 41 50 4e 20 49 6e 73 74 61 6c 6c 20 4d 61 6e 61 67 65 72 } //1 Offercast - APN Install Manager
		$a_81_5 = {4f 43 50 61 63 6b 65 72 2e 70 64 62 } //1 OCPacker.pdb
		$a_81_6 = {55 6e 69 6e 73 74 2e 65 78 65 } //-100 Uninst.exe
		$a_81_7 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //-100 Uninstall.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*-100+(#a_81_7  & 1)*-100) >=6
 
}