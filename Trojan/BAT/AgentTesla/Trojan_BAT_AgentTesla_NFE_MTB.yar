
rule Trojan_BAT_AgentTesla_NFE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NFE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0f 00 00 "
		
	strings :
		$a_01_0 = {78 69 6c 65 63 75 72 69 74 79 5f 41 70 70 6c 69 63 61 74 69 6f 6e 49 64 5f 50 6f 6c 69 63 79 4d 61 6e 61 67 65 6d 65 6e 74 5f 43 6d 64 6c 65 74 73 } //10 xilecurity_ApplicationId_PolicyManagement_Cmdlets
		$a_01_1 = {72 61 73 69 6e 64 6f 77 73 5f 44 78 61 67 6e 6f 73 69 73 5f 54 72 6f 75 62 6c 65 73 68 6f 6f 74 69 6e 67 50 61 63 6b } //10 rasindows_Dxagnosis_TroubleshootingPack
		$a_01_2 = {66 70 34 61 74 74 6f 72 73 5f 48 6f 39 30 30 50 } //10 fp4attors_Ho900P
		$a_01_3 = {49 4d 4a 50 44 6d 5f 44 61 74 61 58 53 41 50 49 } //10 IMJPDm_DataXSAPI
		$a_01_4 = {6d 71 64 79 5f 73 69 6e 67 6c 65 72 65 73 } //10 mqdy_singleres
		$a_01_5 = {53 57 44 49 52 73 6f 66 74 5f 57 65 65 68 76 69 64 } //10 SWDIRsoft_Weehvid
		$a_01_6 = {43 4e 4e 30 6e 74 5f 43 6d 4e 45 41 50 49 } //10 CNN0nt_CmNEAPI
		$a_01_7 = {58 52 50 73 6f 66 74 5f 42 33 30 4a } //10 XRPsoft_B30J
		$a_01_8 = {6d 75 74 6f 5f 42 6c 75 65 74 6f 74 75 70 } //10 muto_Bluetotup
		$a_01_9 = {61 64 70 72 6f 6d 5f 47 6a 65 79 34 30 } //10 adprom_Gjey40
		$a_01_10 = {47 65 74 46 6f 6c 64 65 72 50 61 74 68 } //1 GetFolderPath
		$a_01_11 = {47 65 74 43 75 72 72 65 6e 74 44 69 72 65 63 74 6f 72 79 } //1 GetCurrentDirectory
		$a_01_12 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
		$a_01_13 = {67 65 74 5f 42 61 73 65 44 69 72 65 63 74 6f 72 79 } //1 get_BaseDirectory
		$a_01_14 = {01 57 94 02 28 09 02 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 1b 00 00 00 04 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*10+(#a_01_8  & 1)*10+(#a_01_9  & 1)*10+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1) >=15
 
}