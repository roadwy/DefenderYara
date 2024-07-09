
rule Trojan_BAT_AgentTesla_EB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 d1 c4 d1 c2 20 04 00 00 00 63 20 04 00 00 00 62 20 f6 55 15 f3 61 7d ?? ?? ?? ?? 38 38 02 00 00 7e ?? ?? ?? ?? 20 3a c0 42 be 20 98 89 53 36 58 20 49 5c a0 21 59 20 89 ed f5 d2 61 } //7
	condition:
		((#a_03_0  & 1)*7) >=7
 
}
rule Trojan_BAT_AgentTesla_EB_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 6f 66 74 5f 47 71 63 61 70 } //1 soft_Gqcap
		$a_01_1 = {61 63 6b 5f 75 67 69 } //1 ack_ugi
		$a_01_2 = {66 78 73 6f 6c 69 63 79 5f 52 65 42 52 32 } //1 fxsolicy_ReBR2
		$a_01_3 = {6e 75 62 73 5f 49 6e 74 61 74 63 68 61 } //1 nubs_Intatcha
		$a_01_4 = {4c 6f 63 74 5f 73 63 74 6d 67 74 } //1 Loct_sctmgt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_BAT_AgentTesla_EB_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 04 03 8e 69 5d 91 11 01 04 05 5d 91 61 7e 1a 01 00 04 28 ?? ?? ?? ?? 03 04 17 58 03 8e 69 5d 91 7e 1b 01 00 04 28 ?? ?? ?? ?? 59 11 00 } //5
		$a_01_1 = {54 00 61 00 73 00 6b 00 54 00 72 00 61 00 79 00 41 00 70 00 70 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 TaskTrayApp.Properties.Resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_AgentTesla_EB_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 11 00 00 "
		
	strings :
		$a_81_0 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_81_1 = {4d 61 74 68 45 61 73 79 } //1 MathEasy
		$a_81_2 = {74 6f 54 65 78 74 } //1 toText
		$a_81_3 = {47 5a 49 44 45 4b 4b 4b 4b } //1 GZIDEKKKK
		$a_81_4 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_81_5 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
		$a_81_6 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_7 = {48 69 70 48 6f 70 } //1 HipHop
		$a_81_8 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_81_9 = {4b 65 79 44 65 63 6f 64 65 72 } //1 KeyDecoder
		$a_81_10 = {53 74 72 69 6e 67 53 70 6c 69 74 4f 70 74 69 6f 6e 73 } //1 StringSplitOptions
		$a_81_11 = {75 70 6c 6f 61 64 44 61 74 61 } //1 uploadData
		$a_81_12 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_13 = {64 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 downloadData
		$a_81_14 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_81_15 = {77 53 63 61 6e 43 6f 64 65 } //1 wScanCode
		$a_81_16 = {55 72 69 4b 69 6e 64 } //1 UriKind
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_81_14  & 1)*1+(#a_81_15  & 1)*1+(#a_81_16  & 1)*1) >=17
 
}
rule Trojan_BAT_AgentTesla_EB_MTB_5{
	meta:
		description = "Trojan:BAT/AgentTesla.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 0c 00 00 "
		
	strings :
		$a_81_0 = {24 33 32 32 65 37 65 62 66 2d 39 30 34 31 2d 34 62 37 65 2d 61 66 37 38 2d 63 39 39 32 66 33 34 30 65 64 37 38 } //20 $322e7ebf-9041-4b7e-af78-c992f340ed78
		$a_81_1 = {24 61 66 62 63 33 33 35 65 2d 63 62 36 37 2d 34 32 35 31 2d 62 30 63 33 2d 30 30 66 36 35 63 64 34 37 62 66 38 } //20 $afbc335e-cb67-4251-b0c3-00f65cd47bf8
		$a_81_2 = {24 36 63 61 66 65 64 65 64 2d 65 62 61 34 2d 34 65 31 36 2d 38 66 31 64 2d 63 35 31 36 35 39 62 30 30 35 31 64 } //20 $6cafeded-eba4-4e16-8f1d-c51659b0051d
		$a_81_3 = {49 6d 61 67 65 72 2e 50 6f 64 61 6a 49 6c 6f 73 63 4b 6c 61 73 48 69 73 74 6f 67 72 61 6d 75 47 2e 72 65 73 6f 75 72 63 65 73 } //1 Imager.PodajIloscKlasHistogramuG.resources
		$a_81_4 = {50 68 6f 74 6f 53 6c 69 64 65 43 53 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //1 PhotoSlideCS.Form1.resources
		$a_81_5 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 2e 53 70 6c 61 73 68 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //1 aR3nbf8dQp2feLmk31.SplashForm.resources
		$a_81_6 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_7 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_81_8 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_9 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_81_10 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_11 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*20+(#a_81_2  & 1)*20+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1) >=23
 
}
rule Trojan_BAT_AgentTesla_EB_MTB_6{
	meta:
		description = "Trojan:BAT/AgentTesla.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 0e 00 00 "
		
	strings :
		$a_81_0 = {24 36 63 65 66 66 33 35 61 2d 63 34 37 36 2d 34 66 32 66 2d 39 64 30 38 2d 31 36 63 33 64 39 62 64 35 30 39 31 } //20 $6ceff35a-c476-4f2f-9d08-16c3d9bd5091
		$a_81_1 = {24 39 34 38 30 38 30 39 65 2d 35 34 37 32 2d 34 34 66 33 2d 62 30 37 36 2d 64 63 64 66 37 33 37 39 65 37 36 36 } //20 $9480809e-5472-44f3-b076-dcdf7379e766
		$a_81_2 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_3 = {63 61 70 74 61 69 6e 61 6c 6d 2e 52 65 73 6f 75 72 63 65 73 } //1 captainalm.Resources
		$a_81_4 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_81_5 = {54 72 61 63 6b 4d 61 6e 61 67 65 72 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 TrackManager.My.Resources
		$a_81_6 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //1 DebuggerStepThroughAttribute
		$a_81_7 = {77 65 62 73 68 65 6c 6c 4d 61 6e 61 67 65 72 2e 61 62 6f 75 74 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //1 webshellManager.aboutForm.resources
		$a_81_8 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_9 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_10 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_81_11 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
		$a_81_12 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_13 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*20+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1) >=24
 
}