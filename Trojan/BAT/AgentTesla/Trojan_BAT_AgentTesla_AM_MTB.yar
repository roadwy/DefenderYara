
rule Trojan_BAT_AgentTesla_AM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 06 00 "
		
	strings :
		$a_03_0 = {02 72 35 01 90 01 01 70 28 1a 90 01 02 06 0b 73 49 90 01 02 0a 0c 07 8e 69 13 06 2b 13 00 16 2d 0a 08 07 11 06 91 90 00 } //01 00 
		$a_01_1 = {57 65 62 43 6c 69 65 6e 74 } //01 00  WebClient
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_01_3 = {54 6f 41 72 72 61 79 } //01 00  ToArray
		$a_01_4 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //00 00  get_Assembly
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_AM_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {07 11 04 11 05 6f 90 01 03 0a 26 07 11 04 11 05 6f 90 01 03 0a 28 90 01 03 0a 13 06 09 08 72 90 01 03 70 28 90 01 03 0a 72 90 01 03 70 20 90 01 03 00 14 14 17 8d 90 01 03 01 25 16 11 06 8c 90 01 03 01 a2 6f 90 01 03 0a a5 90 01 03 01 9c 11 05 17 58 13 05 11 05 07 6f 90 01 03 0a 32 a1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_AM_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 03 00 "
		
	strings :
		$a_00_0 = {57 15 02 08 09 01 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 2e 00 00 00 06 00 00 00 05 00 00 00 0f 00 00 00 03 00 00 00 31 } //03 00 
		$a_81_1 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //03 00  get_CurrentDomain
		$a_81_2 = {67 65 74 5f 49 73 52 75 6e 6e 69 6e 67 } //03 00  get_IsRunning
		$a_81_3 = {73 65 74 5f 53 65 63 75 72 69 74 79 50 72 6f 74 6f 63 6f 6c } //03 00  set_SecurityProtocol
		$a_81_4 = {53 65 72 76 69 63 65 50 6f 69 6e 74 4d 61 6e 61 67 65 72 } //03 00  ServicePointManager
		$a_81_5 = {57 65 62 52 65 71 75 65 73 74 } //00 00  WebRequest
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_AM_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 03 00 "
		
	strings :
		$a_00_0 = {01 57 17 a2 1f 09 1f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 ac 00 00 00 2e 00 00 00 e2 } //03 00 
		$a_01_1 = {50 68 6f 65 6e 69 78 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //03 00  Phoenix.Resources.resources
		$a_01_2 = {41 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 4d 6f 64 65 } //03 00  AuthenticationMode
		$a_01_3 = {4d 69 63 72 6f 73 6f 66 74 2e 56 69 73 75 61 6c 42 61 73 69 63 2e 41 70 70 6c 69 63 61 74 69 6f 6e 53 65 72 76 69 63 65 73 } //03 00  Microsoft.VisualBasic.ApplicationServices
		$a_01_4 = {53 68 75 74 64 6f 77 6e 45 76 65 6e 74 48 61 6e 64 6c 65 72 } //03 00  ShutdownEventHandler
		$a_01_5 = {53 68 75 74 64 6f 77 6e 4d 6f 64 65 } //00 00  ShutdownMode
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_AM_MTB_5{
	meta:
		description = "Trojan:BAT/AgentTesla.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {42 75 6e 69 35 35 35 66 75 5f 54 65 35 35 35 35 78 74 42 35 35 35 6f 78 } //01 00  Buni555fu_Te5555xtB555ox
		$a_81_1 = {41 72 65 20 79 6f 75 20 73 75 72 65 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 63 6c 6f 73 65 20 6d 65 21 21 } //01 00  Are you sure you want to close me!!
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00  FromBase64
		$a_81_3 = {4c 61 74 65 42 69 6e 64 69 6e 67 } //01 00  LateBinding
		$a_81_4 = {53 74 72 52 65 76 65 72 73 65 } //01 00  StrReverse
		$a_81_5 = {4b 6e 6f 77 5f 69 66 5f 59 6f 75 72 5f 47 69 72 6c 66 72 69 65 6e 64 5f 49 73 5f 48 6f 72 6e 79 5f 53 74 65 70 5f 31 31 } //01 00  Know_if_Your_Girlfriend_Is_Horny_Step_11
		$a_81_6 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //00 00  CreateInstance
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_AM_MTB_6{
	meta:
		description = "Trojan:BAT/AgentTesla.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 01 00 "
		
	strings :
		$a_81_0 = {42 42 4d 53 2e 46 6f 72 6d 43 75 73 74 6f 6d 65 72 49 6e 66 6f 2e 72 65 73 6f 75 72 63 65 73 } //01 00  BBMS.FormCustomerInfo.resources
		$a_81_1 = {42 42 4d 53 2e 46 6f 72 6d 44 6f 6e 6f 72 49 6e 66 6f 2e 72 65 73 6f 75 72 63 65 73 } //01 00  BBMS.FormDonorInfo.resources
		$a_81_2 = {42 42 4d 53 2e 46 6f 72 6d 44 6f 6e 6f 72 55 70 64 61 74 65 2e 72 65 73 6f 75 72 63 65 73 } //01 00  BBMS.FormDonorUpdate.resources
		$a_81_3 = {42 42 4d 53 2e 46 6f 72 6d 4c 6f 67 69 6e 2e 72 65 73 6f 75 72 63 65 73 } //01 00  BBMS.FormLogin.resources
		$a_81_4 = {42 42 4d 53 2e 46 6f 72 6d 4d 61 69 6e 2e 72 65 73 6f 75 72 63 65 73 } //01 00  BBMS.FormMain.resources
		$a_81_5 = {42 42 4d 53 2e 46 6f 72 6d 52 65 70 6f 72 74 56 69 65 77 65 72 2e 72 65 73 6f 75 72 63 65 73 } //01 00  BBMS.FormReportViewer.resources
		$a_81_6 = {42 42 4d 53 2e 46 6f 72 6d 53 74 6f 63 6b 4c 69 73 74 2e 72 65 73 6f 75 72 63 65 73 } //01 00  BBMS.FormStockList.resources
		$a_81_7 = {42 42 4d 53 2e 46 6f 72 6d 55 73 65 72 41 63 63 6f 75 6e 74 2e 72 65 73 6f 75 72 63 65 73 } //01 00  BBMS.FormUserAccount.resources
		$a_81_8 = {42 42 4d 53 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  BBMS.Resources.resources
		$a_81_9 = {42 42 4d 53 2e 79 79 74 31 2e 72 65 73 6f 75 72 63 65 73 } //01 00  BBMS.yyt1.resources
		$a_81_10 = {57 72 61 70 4e 6f 6e 45 78 63 65 70 74 69 6f 6e 54 68 72 6f 77 73 } //01 00  WrapNonExceptionThrows
		$a_81_11 = {41 72 6e 61 76 20 4d 75 6b 68 6f 70 61 64 68 61 79 } //00 00  Arnav Mukhopadhay
	condition:
		any of ($a_*)
 
}