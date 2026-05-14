
rule _#PUA_Block_GuaGua{
	meta:
		description = "!#PUA:Block:GuaGua,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_81_0 = {67 75 61 67 75 61 } //1 guagua
		$a_81_1 = {47 75 61 47 75 61 2d 53 65 72 76 69 63 65 } //1 GuaGua-Service
		$a_81_2 = {52 65 73 69 64 65 43 6c 69 65 6e 74 2e 65 78 65 } //1 ResideClient.exe
		$a_81_3 = {52 65 73 69 64 65 43 6c 69 65 6e 74 } //1 ResideClient
		$a_81_4 = {55 6e 69 6e 73 74 2e 65 78 65 } //-100 Uninst.exe
		$a_81_5 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //-100 Uninstall.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*-100+(#a_81_5  & 1)*-100) >=4
 
}
rule _#PUA_Block_GuaGua_2{
	meta:
		description = "!#PUA:Block:GuaGua,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_81_0 = {4c 65 62 61 39 39 44 61 74 } //1 Leba99Dat
		$a_81_1 = {4c 65 62 61 39 39 2e 65 78 65 } //1 Leba99.exe
		$a_81_2 = {6c 65 62 61 39 39 20 4d 61 69 6e 20 57 6e 64 } //1 leba99 Main Wnd
		$a_81_3 = {6c 65 62 61 39 39 72 6f 6f 6d } //1 leba99room
		$a_81_4 = {4c 45 42 41 39 39 } //1 LEBA99
		$a_81_5 = {55 6e 69 6e 73 74 2e 65 78 65 } //-100 Uninst.exe
		$a_81_6 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //-100 Uninstall.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*-100+(#a_81_6  & 1)*-100) >=5
 
}
rule _#PUA_Block_GuaGua_3{
	meta:
		description = "!#PUA:Block:GuaGua,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_81_0 = {43 47 75 61 47 75 61 4d 73 67 42 6f 78 44 6c 67 } //1 CGuaGuaMsgBoxDlg
		$a_81_1 = {47 75 61 47 75 61 50 61 74 68 } //1 GuaGuaPath
		$a_81_2 = {67 75 61 67 75 61 5f 73 65 74 75 70 2e 65 78 65 } //1 guagua_setup.exe
		$a_81_3 = {47 55 41 47 55 41 41 43 4f 55 4e 54 49 44 } //1 GUAGUAACOUNTID
		$a_81_4 = {47 75 61 47 75 61 2e 65 78 65 } //1 GuaGua.exe
		$a_81_5 = {55 6e 69 6e 73 74 2e 65 78 65 } //-100 Uninst.exe
		$a_81_6 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //-100 Uninstall.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*-100+(#a_81_6  & 1)*-100) >=5
 
}
rule _#PUA_Block_GuaGua_4{
	meta:
		description = "!#PUA:Block:GuaGua,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_81_0 = {70 69 6e 67 67 75 6f 5f 72 65 6c 65 61 73 65 } //1 pingguo_release
		$a_81_1 = {70 69 6e 67 67 75 6f 35 35 2e 65 78 65 } //1 pingguo55.exe
		$a_81_2 = {70 69 6e 67 67 75 6f 35 35 } //1 pingguo55
		$a_81_3 = {70 69 6e 67 67 75 6f 2e 65 78 65 } //1 pingguo.exe
		$a_81_4 = {67 75 61 67 75 61 5f 64 61 6e 63 65 5f 73 65 74 75 70 2e 65 78 65 } //1 guagua_dance_setup.exe
		$a_81_5 = {55 6e 69 6e 73 74 2e 65 78 65 } //-100 Uninst.exe
		$a_81_6 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //-100 Uninstall.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*-100+(#a_81_6  & 1)*-100) >=5
 
}
rule _#PUA_Block_GuaGua_5{
	meta:
		description = "!#PUA:Block:GuaGua,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_81_0 = {52 65 73 69 64 65 43 6c 69 65 6e 74 } //1 ResideClient
		$a_81_1 = {52 65 73 69 64 65 43 6c 69 65 6e 74 20 56 65 72 73 69 6f 6e 20 31 2e 30 } //1 ResideClient Version 1.0
		$a_81_2 = {52 65 73 69 64 65 43 6c 69 65 6e 74 2e 65 78 65 } //1 ResideClient.exe
		$a_81_3 = {47 75 61 47 75 61 2d 53 65 72 76 69 63 65 } //1 GuaGua-Service
		$a_81_4 = {47 75 61 67 75 61 } //1 Guagua
		$a_81_5 = {55 6e 69 6e 73 74 2e 65 78 65 } //-100 Uninst.exe
		$a_81_6 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //-100 Uninstall.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*-100+(#a_81_6  & 1)*-100) >=5
 
}
rule _#PUA_Block_GuaGua_6{
	meta:
		description = "!#PUA:Block:GuaGua,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_81_0 = {47 75 61 47 75 61 2d 53 65 72 76 69 63 65 } //1 GuaGua-Service
		$a_81_1 = {73 63 20 64 65 6c 65 74 65 20 47 75 61 47 75 61 2d 53 65 72 76 69 63 65 } //1 sc delete GuaGua-Service
		$a_81_2 = {6e 65 74 20 73 74 61 72 74 20 47 75 61 47 75 61 2d 53 65 72 76 69 63 65 } //1 net start GuaGua-Service
		$a_81_3 = {52 65 73 69 64 65 43 6c 69 65 6e 74 2e 65 78 65 } //1 ResideClient.exe
		$a_81_4 = {55 6e 69 6e 73 74 2e 65 78 65 } //-100 Uninst.exe
		$a_81_5 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //-100 Uninstall.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*-100+(#a_81_5  & 1)*-100) >=4
 
}
rule _#PUA_Block_GuaGua_7{
	meta:
		description = "!#PUA:Block:GuaGua,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_81_0 = {4c 54 2e 53 65 72 76 69 63 65 43 6c 69 65 6e 74 } //1 LT.ServiceClient
		$a_81_1 = {4c 54 2e 53 65 72 76 69 63 65 43 6c 69 65 6e 74 2e 65 78 65 } //1 LT.ServiceClient.exe
		$a_81_2 = {4c 54 2e 53 65 72 76 69 63 65 43 6c 69 65 6e 74 2e 4d 61 69 6e 2e 72 65 73 6f 75 72 63 65 73 } //1 LT.ServiceClient.Main.resources
		$a_81_3 = {4c 54 2e 53 65 72 76 69 63 65 43 6c 69 65 6e 74 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 LT.ServiceClient.g.resources
		$a_81_4 = {55 6e 69 6e 73 74 2e 65 78 65 } //-100 Uninst.exe
		$a_81_5 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //-100 Uninstall.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*-100+(#a_81_5  & 1)*-100) >=4
 
}