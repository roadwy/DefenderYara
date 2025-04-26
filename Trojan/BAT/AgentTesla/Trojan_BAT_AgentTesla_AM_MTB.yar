
rule Trojan_BAT_AgentTesla_AM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_03_0 = {02 72 35 01 ?? 70 28 1a ?? ?? 06 0b 73 49 ?? ?? 0a 0c 07 8e 69 13 06 2b 13 00 16 2d 0a 08 07 11 06 91 } //6
		$a_01_1 = {57 65 62 43 6c 69 65 6e 74 } //1 WebClient
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_3 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_01_4 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //1 get_Assembly
	condition:
		((#a_03_0  & 1)*6+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=10
 
}
rule Trojan_BAT_AgentTesla_AM_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 04 11 05 6f ?? ?? ?? 0a 26 07 11 04 11 05 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 06 09 08 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 20 ?? ?? ?? 00 14 14 17 8d ?? ?? ?? 01 25 16 11 06 8c ?? ?? ?? 01 a2 6f ?? ?? ?? 0a a5 ?? ?? ?? 01 9c 11 05 17 58 13 05 11 05 07 6f ?? ?? ?? 0a 32 a1 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_BAT_AgentTesla_AM_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {01 57 96 b6 2b 09 1f 00 00 00 fa 25 33 00 16 00 00 01 } //3
		$a_01_1 = {4d 69 63 72 6f 73 6f 66 74 2e 56 69 73 75 61 6c 42 61 73 69 63 2e 41 70 70 6c 69 63 61 74 69 6f 6e 53 65 72 76 69 63 65 73 } //1 Microsoft.VisualBasic.ApplicationServices
		$a_01_2 = {73 65 74 5f 55 73 65 41 6e 74 69 41 6c 69 61 73 } //1 set_UseAntiAlias
		$a_01_3 = {73 65 74 5f 50 61 73 73 77 6f 72 64 43 68 61 72 } //1 set_PasswordChar
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}
rule Trojan_BAT_AgentTesla_AM_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_00_0 = {57 15 02 08 09 01 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 2e 00 00 00 06 00 00 00 05 00 00 00 0f 00 00 00 03 00 00 00 31 } //3
		$a_81_1 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //3 get_CurrentDomain
		$a_81_2 = {67 65 74 5f 49 73 52 75 6e 6e 69 6e 67 } //3 get_IsRunning
		$a_81_3 = {73 65 74 5f 53 65 63 75 72 69 74 79 50 72 6f 74 6f 63 6f 6c } //3 set_SecurityProtocol
		$a_81_4 = {53 65 72 76 69 63 65 50 6f 69 6e 74 4d 61 6e 61 67 65 72 } //3 ServicePointManager
		$a_81_5 = {57 65 62 52 65 71 75 65 73 74 } //3 WebRequest
	condition:
		((#a_00_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3) >=18
 
}
rule Trojan_BAT_AgentTesla_AM_MTB_5{
	meta:
		description = "Trojan:BAT/AgentTesla.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_00_0 = {01 57 17 a2 1f 09 1f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 ac 00 00 00 2e 00 00 00 e2 } //3
		$a_01_1 = {50 68 6f 65 6e 69 78 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //3 Phoenix.Resources.resources
		$a_01_2 = {41 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 4d 6f 64 65 } //3 AuthenticationMode
		$a_01_3 = {4d 69 63 72 6f 73 6f 66 74 2e 56 69 73 75 61 6c 42 61 73 69 63 2e 41 70 70 6c 69 63 61 74 69 6f 6e 53 65 72 76 69 63 65 73 } //3 Microsoft.VisualBasic.ApplicationServices
		$a_01_4 = {53 68 75 74 64 6f 77 6e 45 76 65 6e 74 48 61 6e 64 6c 65 72 } //3 ShutdownEventHandler
		$a_01_5 = {53 68 75 74 64 6f 77 6e 4d 6f 64 65 } //3 ShutdownMode
	condition:
		((#a_00_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3) >=18
 
}
rule Trojan_BAT_AgentTesla_AM_MTB_6{
	meta:
		description = "Trojan:BAT/AgentTesla.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {42 75 6e 69 35 35 35 66 75 5f 54 65 35 35 35 35 78 74 42 35 35 35 6f 78 } //1 Buni555fu_Te5555xtB555ox
		$a_81_1 = {41 72 65 20 79 6f 75 20 73 75 72 65 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 63 6c 6f 73 65 20 6d 65 21 21 } //1 Are you sure you want to close me!!
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
		$a_81_3 = {4c 61 74 65 42 69 6e 64 69 6e 67 } //1 LateBinding
		$a_81_4 = {53 74 72 52 65 76 65 72 73 65 } //1 StrReverse
		$a_81_5 = {4b 6e 6f 77 5f 69 66 5f 59 6f 75 72 5f 47 69 72 6c 66 72 69 65 6e 64 5f 49 73 5f 48 6f 72 6e 79 5f 53 74 65 70 5f 31 31 } //1 Know_if_Your_Girlfriend_Is_Horny_Step_11
		$a_81_6 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}
rule Trojan_BAT_AgentTesla_AM_MTB_7{
	meta:
		description = "Trojan:BAT/AgentTesla.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_81_0 = {42 42 4d 53 2e 46 6f 72 6d 43 75 73 74 6f 6d 65 72 49 6e 66 6f 2e 72 65 73 6f 75 72 63 65 73 } //1 BBMS.FormCustomerInfo.resources
		$a_81_1 = {42 42 4d 53 2e 46 6f 72 6d 44 6f 6e 6f 72 49 6e 66 6f 2e 72 65 73 6f 75 72 63 65 73 } //1 BBMS.FormDonorInfo.resources
		$a_81_2 = {42 42 4d 53 2e 46 6f 72 6d 44 6f 6e 6f 72 55 70 64 61 74 65 2e 72 65 73 6f 75 72 63 65 73 } //1 BBMS.FormDonorUpdate.resources
		$a_81_3 = {42 42 4d 53 2e 46 6f 72 6d 4c 6f 67 69 6e 2e 72 65 73 6f 75 72 63 65 73 } //1 BBMS.FormLogin.resources
		$a_81_4 = {42 42 4d 53 2e 46 6f 72 6d 4d 61 69 6e 2e 72 65 73 6f 75 72 63 65 73 } //1 BBMS.FormMain.resources
		$a_81_5 = {42 42 4d 53 2e 46 6f 72 6d 52 65 70 6f 72 74 56 69 65 77 65 72 2e 72 65 73 6f 75 72 63 65 73 } //1 BBMS.FormReportViewer.resources
		$a_81_6 = {42 42 4d 53 2e 46 6f 72 6d 53 74 6f 63 6b 4c 69 73 74 2e 72 65 73 6f 75 72 63 65 73 } //1 BBMS.FormStockList.resources
		$a_81_7 = {42 42 4d 53 2e 46 6f 72 6d 55 73 65 72 41 63 63 6f 75 6e 74 2e 72 65 73 6f 75 72 63 65 73 } //1 BBMS.FormUserAccount.resources
		$a_81_8 = {42 42 4d 53 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 BBMS.Resources.resources
		$a_81_9 = {42 42 4d 53 2e 79 79 74 31 2e 72 65 73 6f 75 72 63 65 73 } //1 BBMS.yyt1.resources
		$a_81_10 = {57 72 61 70 4e 6f 6e 45 78 63 65 70 74 69 6f 6e 54 68 72 6f 77 73 } //1 WrapNonExceptionThrows
		$a_81_11 = {41 72 6e 61 76 20 4d 75 6b 68 6f 70 61 64 68 61 79 } //1 Arnav Mukhopadhay
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1) >=12
 
}