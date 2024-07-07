
rule Trojan_BAT_AgentTesla_EC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_00_0 = {11 07 11 01 03 11 01 91 11 03 61 d2 9c } //10
		$a_81_1 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_2 = {47 65 74 44 6f 6d 61 69 6e } //1 GetDomain
		$a_81_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=13
 
}
rule Trojan_BAT_AgentTesla_EC_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {54 72 61 70 64 6f 6f 72 } //1 Trapdoor
		$a_81_1 = {48 74 74 70 57 65 62 52 65 71 75 65 73 74 } //1 HttpWebRequest
		$a_81_2 = {75 61 77 41 6e 50 73 6e } //1 uawAnPsn
		$a_81_3 = {52 65 67 65 78 4f 70 74 69 6f 6e 73 } //1 RegexOptions
		$a_81_4 = {47 65 74 52 65 73 70 6f 6e 73 65 } //1 GetResponse
		$a_81_5 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_81_6 = {53 65 63 75 72 69 74 79 50 72 6f 74 6f 63 6f 6c 54 79 70 65 } //1 SecurityProtocolType
		$a_81_7 = {54 6f 53 74 72 69 6e 67 } //1 ToString
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}
rule Trojan_BAT_AgentTesla_EC_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {2f 00 57 00 64 00 4b 00 61 00 63 00 6c 00 76 00 3b 00 63 00 6f 00 6d 00 70 00 6f 00 6e 00 65 00 6e 00 74 00 2f 00 6d 00 61 00 69 00 6e 00 77 00 69 00 6e 00 64 00 6f 00 77 00 2e 00 78 00 61 00 6d 00 6c 00 } //1 /WdKaclv;component/mainwindow.xaml
		$a_01_1 = {63 00 68 00 65 00 63 00 6b 00 32 00 35 00 30 00 30 00 77 00 } //1 check2500w
		$a_01_2 = {67 65 74 5f 52 65 73 6f 75 72 63 65 4d 61 6e 61 67 65 72 } //1 get_ResourceManager
		$a_01_3 = {57 64 4b 61 63 6c 76 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 WdKaclv.g.resources
		$a_01_4 = {52 65 61 63 74 69 6f 6e 44 69 66 66 75 73 69 6f 6e 4c 69 62 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 ReactionDiffusionLib.Properties.Resources.resources
		$a_01_5 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Trojan_BAT_AgentTesla_EC_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 50 00 6e 00 50 00 45 00 6e 00 74 00 69 00 74 00 79 00 } //1 SELECT * FROM Win32_PnPEntity
		$a_01_1 = {43 00 4f 00 4d 00 20 00 70 00 6f 00 72 00 74 00 20 00 52 00 58 00 20 00 64 00 61 00 74 00 61 00 20 00 74 00 68 00 72 00 65 00 61 00 64 00 } //1 COM port RX data thread
		$a_01_2 = {74 65 72 6d 69 6e 61 6c 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 terminal.Resources.resources
		$a_01_3 = {41 00 6e 00 6e 00 61 00 43 00 6c 00 61 00 72 00 6b 00 4e 00 75 00 64 00 65 00 32 00 35 00 } //1 AnnaClarkNude25
		$a_01_4 = {46 00 53 00 41 00 46 00 53 00 46 00 41 00 46 00 41 00 53 00 46 00 41 00 53 00 46 00 41 00 46 00 53 00 46 00 41 00 46 00 53 00 46 00 41 00 } //1 FSAFSFAFASFASFAFSFAFSFA
		$a_01_5 = {48 69 64 65 4d 6f 64 75 6c 65 4e 61 6d 65 41 74 74 72 69 62 75 74 65 } //1 HideModuleNameAttribute
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Trojan_BAT_AgentTesla_EC_MTB_5{
	meta:
		description = "Trojan:BAT/AgentTesla.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 11 00 00 "
		
	strings :
		$a_81_0 = {24 37 64 62 62 36 32 35 30 2d 64 32 38 32 2d 34 34 64 61 2d 61 61 63 38 2d 64 62 34 37 64 37 33 38 36 36 32 33 } //20 $7dbb6250-d282-44da-aac8-db47d7386623
		$a_81_1 = {24 63 32 62 34 34 31 33 35 2d 66 31 61 63 2d 34 38 61 39 2d 62 64 37 30 2d 33 62 65 32 63 33 38 63 32 61 31 35 } //20 $c2b44135-f1ac-48a9-bd70-3be2c38c2a15
		$a_01_2 = {24 37 38 39 42 32 32 35 42 2d 41 35 41 45 2d 34 44 43 33 2d 38 43 34 34 2d 34 33 45 42 35 31 30 32 32 46 37 43 } //20 $789B225B-A5AE-4DC3-8C44-43EB51022F7C
		$a_81_3 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_4 = {53 74 72 65 61 6d 73 68 69 70 5f 53 63 72 65 65 6e 73 68 6f 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Streamship_Screenshot.Properties.Resources.resources
		$a_81_5 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_81_6 = {43 50 45 32 30 30 4c 61 62 31 2e 45 78 74 65 6e 64 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //1 CPE200Lab1.ExtendForm.resources
		$a_81_7 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //1 DebuggerStepThroughAttribute
		$a_81_8 = {43 6c 6f 77 6e 66 69 73 68 56 6f 69 63 65 43 68 61 6e 67 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 ClownfishVoiceChanger.Properties.Resources.resources
		$a_81_9 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_10 = {41 70 70 5f 5f 42 65 74 61 5f 2e 45 61 73 79 2e 72 65 73 6f 75 72 63 65 73 } //1 App__Beta_.Easy.resources
		$a_81_11 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_12 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_81_13 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
		$a_81_14 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_15 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_81_16 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*20+(#a_01_2  & 1)*20+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_81_14  & 1)*1+(#a_81_15  & 1)*1+(#a_81_16  & 1)*1) >=23
 
}