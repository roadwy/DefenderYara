
rule _#PUA_Block_PornTool{
	meta:
		description = "!#PUA:Block:PornTool,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {42 79 20 20 53 65 78 38 2e 43 43 } //1 By  Sex8.CC
		$a_81_1 = {31 72 6f 6f 6d 2e 63 63 } //1 1room.cc
		$a_81_2 = {79 6f 67 61 73 65 62 61 2e 63 6f 6d } //2 yogaseba.com
		$a_81_3 = {54 6f 6f 6c 42 61 72 73 } //1 ToolBars
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*2+(#a_81_3  & 1)*1) >=4
 
}
rule _#PUA_Block_PornTool_2{
	meta:
		description = "!#PUA:Block:PornTool,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {53 65 78 38 2e 43 43 } //Sex8.CC  1
		$a_80_1 = {42 72 6f 77 73 65 72 5f 43 6f 6e 74 72 6f 6c } //Browser_Control  1
		$a_80_2 = {43 57 65 62 42 72 6f 77 73 65 72 32 } //CWebBrowser2  1
		$a_80_3 = {31 72 6f 6f 6d 2e 63 63 } //1room.cc  1
		$a_80_4 = {79 6f 67 61 73 65 62 61 2e 63 6f 6d } //yogaseba.com  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}
rule _#PUA_Block_PornTool_3{
	meta:
		description = "!#PUA:Block:PornTool,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {64 6f 77 6e 6c 6f 61 64 2e 72 65 35 38 2e 63 6e } //download.re58.cn  1
		$a_80_1 = {64 2e 72 65 37 31 2e 63 6e } //d.re71.cn  1
		$a_80_2 = {63 6a 2e 67 75 61 67 75 61 2e 63 6e } //cj.guagua.cn  1
		$a_80_3 = {67 75 61 67 75 61 5f 64 61 6e 63 65 5f 73 65 74 75 70 2e 65 78 65 } //guagua_dance_setup.exe  1
		$a_80_4 = {47 69 72 6c 53 68 6f 77 2e 65 78 65 } //GirlShow.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}
rule _#PUA_Block_PornTool_4{
	meta:
		description = "!#PUA:Block:PornTool,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {47 65 74 41 63 74 69 76 65 57 69 6e 64 6f 77 } //GetActiveWindow  1
		$a_80_1 = {47 65 74 55 73 65 72 4f 62 6a 65 63 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 41 } //GetUserObjectInformationA  1
		$a_80_2 = {53 65 78 38 2e 43 43 } //Sex8.CC  1
		$a_80_3 = {42 72 6f 77 73 65 72 5f 43 6f 6e 74 72 6f 6c } //Browser_Control  1
		$a_80_4 = {43 57 65 62 42 72 6f 77 73 65 72 32 } //CWebBrowser2  1
		$a_80_5 = {75 72 6c 38 2e 63 63 } //url8.cc  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}
rule _#PUA_Block_PornTool_5{
	meta:
		description = "!#PUA:Block:PornTool,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_80_0 = {63 6a 74 79 70 65 } //cjtype  1
		$a_80_1 = {73 68 6f 77 70 72 6f 64 75 63 74 } //showproduct  1
		$a_80_2 = {6d 6f 62 69 6c 65 63 6f 6e 6e 65 63 74 } //mobileconnect  1
		$a_80_3 = {67 75 61 67 75 61 2e 63 6e } //guagua.cn  1
		$a_80_4 = {52 65 73 69 64 65 43 6c 69 65 6e 74 2e 65 78 65 } //ResideClient.exe  1
		$a_80_5 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_6 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //Uninstall.exe  -100
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*-100+(#a_80_6  & 1)*-100) >=5
 
}