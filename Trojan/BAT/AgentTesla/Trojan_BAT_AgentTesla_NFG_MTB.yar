
rule Trojan_BAT_AgentTesla_NFG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NFG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 08 00 00 "
		
	strings :
		$a_01_0 = {24 61 63 66 34 38 66 62 30 2d 36 34 39 38 2d 34 63 32 30 2d 62 36 35 31 2d 33 66 66 61 65 31 37 63 37 61 64 31 } //3 $acf48fb0-6498-4c20-b651-3ffae17c7ad1
		$a_01_1 = {44 6c 49 6d 61 67 65 50 61 72 73 72 2e 50 72 6f 70 65 72 74 69 65 73 } //3 DlImageParsr.Properties
		$a_01_2 = {57 b7 a2 3d 09 0f 00 00 00 00 00 00 00 00 00 00 01 } //3
		$a_01_3 = {20 00 32 01 00 8d } //3
		$a_01_4 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_01_5 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_6 = {43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 } //1 ColorTranslator
		$a_01_7 = {54 6f 57 69 6e 33 32 } //1 ToWin32
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=16
 
}
rule Trojan_BAT_AgentTesla_NFG_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NFG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0b 00 00 "
		
	strings :
		$a_01_0 = {57 53 32 65 62 5f 4d 61 6e 61 67 75 73 33 } //10 WS2eb_Managus3
		$a_01_1 = {69 72 33 77 73 5f 30 63 30 61 } //10 ir3ws_0c0a
		$a_01_2 = {6d 6d 63 62 6f 66 74 5f 47 73 72 73 72 76 } //10 mmcboft_Gsrsrv
		$a_01_3 = {56 61 75 6c 74 63 72 6f 73 6f 66 74 5f 73 76 63 } //10 Vaultcrosoft_svc
		$a_01_4 = {43 4e 42 73 5f 48 61 6e 64 6c 65 72 73 } //10 CNBs_Handlers
		$a_01_5 = {4b 42 53 43 5a 73 6f 66 74 5f 49 64 73 78 74 } //10 KBSCZsoft_Idsxt
		$a_01_6 = {47 65 74 46 6f 6c 64 65 72 50 61 74 68 } //1 GetFolderPath
		$a_01_7 = {47 65 74 43 75 72 72 65 6e 74 44 69 72 65 63 74 6f 72 79 } //1 GetCurrentDirectory
		$a_01_8 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
		$a_01_9 = {67 65 74 5f 42 61 73 65 44 69 72 65 63 74 6f 72 79 } //1 get_BaseDirectory
		$a_03_10 = {01 57 94 02 28 09 02 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 90 01 01 00 00 00 04 00 00 00 90 00 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_03_10  & 1)*1) >=15
 
}