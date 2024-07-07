
rule Trojan_BAT_AgentTesla_ED_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0a 0a 02 8e 69 8d 90 01 04 0b 16 0c 2b 15 00 07 08 02 08 91 06 08 06 8e 69 5d 91 61 d2 9c 00 08 17 58 0c 08 02 8e 69 fe 04 13 04 11 04 2d df 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_BAT_AgentTesla_ED_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {02 7b 07 00 00 04 0c 02 08 02 7b 06 00 00 04 58 02 7b 04 00 00 04 58 20 8d 3b e0 7c 02 7b 09 00 00 04 58 61 7d 07 00 00 04 02 08 7d 06 00 00 04 } //3
		$a_01_1 = {4e 00 6f 00 74 00 65 00 50 00 61 00 64 00 20 00 50 00 52 00 6f 00 } //1 NotePad PRo
		$a_01_2 = {45 00 73 00 6d 00 61 00 69 00 6c 00 20 00 45 00 4c 00 20 00 42 00 6f 00 42 00 } //1 Esmail EL BoB
		$a_01_3 = {73 65 74 5f 55 72 6c } //1 set_Url
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}
rule Trojan_BAT_AgentTesla_ED_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.ED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_00_0 = {fa 01 33 00 16 00 00 01 00 00 00 1d 01 00 00 0f 01 00 00 db 03 00 00 bc 07 00 00 ec 06 } //3
		$a_81_1 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //3 DownloadFile
		$a_81_2 = {67 65 74 5f 41 62 73 6f 6c 75 74 65 50 61 74 68 } //3 get_AbsolutePath
		$a_81_3 = {67 65 74 5f 43 6f 6e 6e 65 63 74 69 6f 6e 53 74 72 69 6e 67 } //3 get_ConnectionString
		$a_81_4 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //3 DebuggerHiddenAttribute
		$a_81_5 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //3 DebuggerNonUserCodeAttribute
	condition:
		((#a_00_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3) >=18
 
}
rule Trojan_BAT_AgentTesla_ED_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.ED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {01 57 9f a2 2b 09 0f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 88 00 00 00 44 00 00 00 52 } //2
		$a_01_1 = {4f 70 68 74 68 61 6c 6d 69 63 } //1 Ophthalmic
		$a_01_2 = {48 74 74 70 4c 69 73 74 65 6e 65 72 43 6f 6e 74 65 78 74 } //1 HttpListenerContext
		$a_01_3 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 56 00 6f 00 6c 00 75 00 6d 00 65 00 43 00 68 00 61 00 6e 00 67 00 65 00 45 00 76 00 65 00 6e 00 74 00 } //1 SELECT * FROM Win32_VolumeChangeEvent
		$a_01_4 = {47 00 34 00 44 00 35 00 34 00 43 00 37 00 44 00 34 00 38 00 41 00 35 00 37 00 45 00 34 00 37 00 59 00 38 00 37 00 48 00 42 00 34 00 } //1 G4D54C7D48A57E47Y87HB4
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}
rule Trojan_BAT_AgentTesla_ED_MTB_5{
	meta:
		description = "Trojan:BAT/AgentTesla.ED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {fa 01 33 00 16 00 00 01 00 00 00 9f 00 00 00 5c 00 00 00 7f 02 00 00 c8 02 00 00 29 02 } //1
		$a_01_1 = {53 00 31 00 54 00 31 00 55 00 31 00 56 00 34 00 57 00 34 00 58 00 } //1 S1T1U1V4W4X
		$a_01_2 = {53 00 61 00 6e 00 66 00 6f 00 72 00 64 00 2e 00 4d 00 75 00 6c 00 74 00 69 00 6d 00 65 00 64 00 69 00 61 00 2e 00 4d 00 69 00 64 00 69 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 Sanford.Multimedia.Midi.Properties.Resources
		$a_01_3 = {4d 75 6c 74 69 6d 65 64 69 61 2e 4d 69 64 69 2e 55 49 2e 44 65 76 69 63 65 } //1 Multimedia.Midi.UI.Device
		$a_01_4 = {45 6e 61 62 6c 65 56 69 73 75 61 6c 53 74 79 6c 65 73 } //1 EnableVisualStyles
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_BAT_AgentTesla_ED_MTB_6{
	meta:
		description = "Trojan:BAT/AgentTesla.ED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,24 00 24 00 0a 00 00 "
		
	strings :
		$a_81_0 = {54 68 65 6d 69 6e 67 53 68 61 72 70 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //10 ThemingSharper.Properties.Resources
		$a_81_1 = {54 68 65 6d 69 6e 67 53 68 61 72 70 65 72 2e 46 6f 72 67 6f 74 50 61 73 73 77 6f 72 64 2e 72 65 73 6f 75 72 63 65 73 } //10 ThemingSharper.ForgotPassword.resources
		$a_81_2 = {54 68 65 6d 69 6e 67 53 68 61 72 70 65 72 2e 50 61 79 6d 65 6e 74 2e 72 65 73 6f 75 72 63 65 73 } //10 ThemingSharper.Payment.resources
		$a_81_3 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //1 GetTypeFromHandle
		$a_81_4 = {47 65 74 45 6c 65 6d 65 6e 74 54 79 70 65 } //1 GetElementType
		$a_81_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_6 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
		$a_81_7 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_81_8 = {42 69 74 6d 61 70 } //1 Bitmap
		$a_81_9 = {47 65 74 54 79 70 65 } //1 GetType
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*10+(#a_81_2  & 1)*10+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=36
 
}
rule Trojan_BAT_AgentTesla_ED_MTB_7{
	meta:
		description = "Trojan:BAT/AgentTesla.ED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 11 00 00 "
		
	strings :
		$a_01_0 = {24 33 30 35 30 44 30 41 34 2d 42 42 44 37 2d 34 43 44 44 2d 42 35 44 38 2d 32 39 38 31 46 45 36 44 34 32 36 31 } //20 $3050D0A4-BBD7-4CDD-B5D8-2981FE6D4261
		$a_81_1 = {24 32 38 35 38 31 34 65 65 2d 34 36 32 31 2d 34 35 32 64 2d 39 30 32 61 2d 39 64 31 64 65 30 37 62 35 30 36 65 } //20 $285814ee-4621-452d-902a-9d1de07b506e
		$a_81_2 = {24 37 62 37 66 62 37 32 66 2d 36 36 32 31 2d 34 34 65 37 2d 62 33 36 37 2d 37 63 63 33 30 38 62 65 65 32 36 65 } //20 $7b7fb72f-6621-44e7-b367-7cc308bee26e
		$a_81_3 = {24 30 63 65 64 63 39 30 66 2d 36 66 39 31 2d 34 36 62 31 2d 62 39 31 32 2d 64 61 35 36 32 66 33 63 30 36 39 35 } //20 $0cedc90f-6f91-46b1-b912-da562f3c0695
		$a_81_4 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_5 = {52 65 62 6f 6f 74 5f 49 4d 47 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Reboot_IMG.Properties.Resources.resources
		$a_81_6 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_81_7 = {6f 6b 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 ok.My.Resources
		$a_81_8 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //1 DebuggerStepThroughAttribute
		$a_81_9 = {54 50 32 5f 50 72 6f 67 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 TP2_Prog.Resources.resources
		$a_81_10 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_11 = {73 74 62 63 2e 4d 44 49 50 61 72 65 6e 74 31 2e 72 65 73 6f 75 72 63 65 73 } //1 stbc.MDIParent1.resources
		$a_81_12 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_13 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_81_14 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
		$a_81_15 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_16 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
	condition:
		((#a_01_0  & 1)*20+(#a_81_1  & 1)*20+(#a_81_2  & 1)*20+(#a_81_3  & 1)*20+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_81_14  & 1)*1+(#a_81_15  & 1)*1+(#a_81_16  & 1)*1) >=24
 
}