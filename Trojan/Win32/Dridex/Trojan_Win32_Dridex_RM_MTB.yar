
rule Trojan_Win32_Dridex_RM_MTB{
	meta:
		description = "Trojan:Win32/Dridex.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 ca 81 c2 01 00 00 00 66 8b 75 8e 66 89 c7 66 31 fe 66 89 75 8e 89 95 44 ff ff ff 8a 19 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dridex_RM_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 c7 38 7a 0c 01 89 90 01 05 89 90 02 07 b2 90 01 01 f6 ea 8a d8 02 1d 90 01 04 83 c5 04 81 fd 79 20 00 00 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dridex_RM_MTB_3{
	meta:
		description = "Trojan:Win32/Dridex.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_81_0 = {72 65 73 65 61 72 63 68 65 72 73 2c 57 72 65 73 75 6c 74 73 74 68 65 6c 76 6d 75 73 65 72 59 } //01 00  researchers,WresultsthelvmuserY
		$a_81_1 = {64 75 65 35 70 74 61 63 69 74 67 62 79 52 74 73 69 67 2c 4c } //01 00  due5ptacitgbyRtsig,L
		$a_81_2 = {37 2c 62 65 72 63 68 72 61 72 6b 73 2c 6a 47 56 72 72 74 65 73 74 69 6e 67 2e 31 38 31 73 74 72 74 65 74 2e 31 31 34 } //00 00  7,berchrarks,jGVrrtesting.181strtet.114
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dridex_RM_MTB_4{
	meta:
		description = "Trojan:Win32/Dridex.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {9b de 0f ac 8f 0f e9 31 7c 2f 2e c6 99 30 cf d5 60 30 44 69 7a 3a 60 71 27 4d a3 82 4b 0a db d5 7b fd 8f cb 5c 5b e9 51 30 2f ae b2 b8 11 50 09 } //01 00 
		$a_81_1 = {4c 64 72 47 65 74 50 72 6f 63 65 64 75 72 65 41 } //01 00  LdrGetProcedureA
		$a_81_2 = {48 69 64 65 43 61 72 65 74 } //01 00  HideCaret
		$a_81_3 = {6e 74 64 6c 6c 2e 64 6c } //01 00  ntdll.dl
		$a_81_4 = {4f 75 74 70 75 74 44 65 62 75 67 53 74 72 69 6e 67 41 } //01 00  OutputDebugStringA
		$a_81_5 = {4e 65 74 43 6f 6e 6e 65 63 74 69 6f 6e 45 6e 75 6d } //00 00  NetConnectionEnum
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dridex_RM_MTB_5{
	meta:
		description = "Trojan:Win32/Dridex.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {45 53 45 4e 54 2e 64 6c 6c } //01 00  ESENT.dll
		$a_81_1 = {55 6e 68 6f 6f 6b 57 69 6e 45 76 65 6e 74 } //01 00  UnhookWinEvent
		$a_81_2 = {43 72 79 70 74 49 6d 70 6f 72 74 50 75 62 6c 69 63 4b 65 79 49 6e 66 6f } //01 00  CryptImportPublicKeyInfo
		$a_81_3 = {53 43 61 72 64 45 6e 64 54 72 61 6e 73 61 63 74 69 6f 6e } //01 00  SCardEndTransaction
		$a_81_4 = {57 69 6e 53 43 61 72 64 2e 64 6c 6c } //01 00  WinSCard.dll
		$a_81_5 = {43 4d 5f 47 65 74 5f 4e 65 78 74 5f 4c 6f 67 5f 43 6f 6e 66 } //ce ff  CM_Get_Next_Log_Conf
		$a_81_6 = {62 43 6f 6e 66 69 67 52 65 73 69 64 38 53 75 62 74 72 61 63 74 69 6f 6e } //00 00  bConfigResid8Subtraction
	condition:
		any of ($a_*)
 
}