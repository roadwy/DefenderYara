
rule Trojan_BAT_AgentTesla_E_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {69 6e 73 74 61 6c 6c 75 74 69 6c 20 2f 6c 6f 67 74 6f 63 6f 6e 73 6f 6c 65 3d 66 61 6c 73 65 20 2f 6c 6f 67 66 69 6c 65 3d 20 2f 75 20 22 20 26 20 43 68 72 77 28 33 34 29 20 26 20 22 25 90 02 06 25 22 20 26 20 43 68 72 77 28 33 34 29 90 00 } //01 00 
		$a_01_1 = {73 74 72 73 20 3d 20 73 74 72 28 29 } //01 00  strs = str()
		$a_01_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 72 75 6e 20 73 74 72 73 2c 30 2c 66 61 6c 73 65 } //00 00  CreateObject("WScript.Shell").run strs,0,false
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_E_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_00_0 = {0f 00 00 00 1e 01 00 00 aa } //03 00 
		$a_81_1 = {54 65 6c 6c 69 67 65 6e 74 20 45 76 6f 6c 75 74 69 6f 6e 20 70 6c 61 74 66 6f 72 6d } //03 00  Telligent Evolution platform
		$a_81_2 = {41 6c 65 78 20 43 72 6f 6d 65 } //03 00  Alex Crome
		$a_81_3 = {50 65 72 6d 69 73 73 69 6f 6e 56 69 65 77 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //03 00  PermissionViewer.Properties.Resources.resources
		$a_81_4 = {48 74 74 70 53 74 61 74 75 73 43 6f 64 65 } //03 00  HttpStatusCode
		$a_81_5 = {48 74 74 70 57 65 62 52 65 73 70 6f 6e 73 65 } //03 00  HttpWebResponse
		$a_81_6 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  ToBase64String
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_E_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 03 00 "
		
	strings :
		$a_00_0 = {57 d5 a2 eb 09 1f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 90 00 00 00 12 00 00 00 97 00 00 00 4a 02 00 00 bb 00 00 00 fa } //03 00 
		$a_81_1 = {4d 69 63 72 6f 73 6f 66 74 2e 56 69 73 75 61 6c 42 61 73 69 63 2e 44 65 76 69 63 65 73 } //03 00  Microsoft.VisualBasic.Devices
		$a_81_2 = {53 68 61 6b 65 4f 66 54 68 65 44 61 79 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //03 00  ShakeOfTheDay.Resources.resources
		$a_81_3 = {53 71 6c 43 6f 6e 6e 65 63 74 69 6f 6e } //03 00  SqlConnection
		$a_81_4 = {53 79 73 74 65 6d 2e 44 61 74 61 2e 53 71 6c 43 6c 69 65 6e 74 } //03 00  System.Data.SqlClient
		$a_81_5 = {53 65 72 76 69 63 65 73 2e 50 72 6f 74 6f 63 6f 6c 73 2e 53 6f 61 70 48 74 74 70 43 6c 69 65 6e 74 50 72 6f 74 6f 63 6f 6c } //00 00  Services.Protocols.SoapHttpClientProtocol
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_E_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {56 00 49 00 50 00 45 00 54 00 53 00 44 00 59 00 53 00 59 00 55 00 59 00 53 00 44 00 59 00 53 00 53 00 49 00 55 00 53 00 55 00 44 00 59 00 55 00 53 00 44 00 55 00 49 00 53 00 44 00 2e 00 56 00 49 00 50 00 45 00 54 00 53 00 44 00 59 00 53 00 59 00 55 00 59 00 53 00 44 00 59 00 53 00 53 00 49 00 55 00 53 00 55 00 44 00 59 00 55 00 53 00 44 00 55 00 49 00 53 00 44 00 } //01 00  VIPETSDYSYUYSDYSSIUSUDYUSDUISD.VIPETSDYSYUYSDYSSIUSUDYUSDUISD
		$a_81_1 = {55 73 65 72 73 5c 56 49 43 54 4f 52 } //01 00  Users\VICTOR
		$a_01_2 = {48 00 65 00 6c 00 6c 00 6f 00 20 00 57 00 6f 00 72 00 6c 00 64 00 21 00 } //01 00  Hello World!
		$a_01_3 = {2e 00 30 00 30 00 30 00 77 00 65 00 62 00 68 00 6f 00 73 00 74 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 56 00 49 00 50 00 45 00 54 00 53 00 44 00 59 00 53 00 59 00 55 00 59 00 53 00 44 00 59 00 53 00 53 00 49 00 55 00 53 00 55 00 44 00 59 00 55 00 53 00 44 00 55 00 49 00 53 00 44 00 2e 00 64 00 6c 00 6c 00 } //01 00  .000webhostapp.com/VIPETSDYSYUYSDYSSIUSUDYUSDUISD.dll
		$a_01_4 = {20 00 01 00 00 14 11 05 11 04 74 01 00 00 1b 6f } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_E_MTB_5{
	meta:
		description = "Trojan:BAT/AgentTesla.E!MTB,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 00 69 00 67 00 68 00 73 00 63 00 6f 00 72 00 65 00 73 00 2e 00 64 00 61 00 74 00 } //01 00  highscores.dat
		$a_01_1 = {47 61 6d 65 4d 61 6e 61 67 65 72 } //01 00  GameManager
		$a_01_2 = {61 64 64 5f 47 61 6d 65 4f 76 65 72 } //01 00  add_GameOver
		$a_01_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  IsDebuggerPresent
		$a_01_4 = {4f 75 74 70 75 74 44 65 62 75 67 53 74 72 69 6e 67 } //01 00  OutputDebugString
		$a_01_5 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_6 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  CheckRemoteDebuggerPresent
		$a_01_7 = {4e 74 51 75 65 72 79 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73 } //00 00  NtQueryInformationProcess
	condition:
		any of ($a_*)
 
}