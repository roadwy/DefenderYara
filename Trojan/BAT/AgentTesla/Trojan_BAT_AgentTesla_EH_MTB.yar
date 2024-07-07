
rule Trojan_BAT_AgentTesla_EH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 0a 1f 18 fe 01 2c 19 07 07 8e 69 17 63 8f 90 01 04 25 47 06 1a 58 4a d2 61 d2 52 1f 19 13 0a 90 00 } //6
	condition:
		((#a_03_0  & 1)*6) >=6
 
}
rule Trojan_BAT_AgentTesla_EH_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {09 11 04 19 5a 11 05 58 08 6f 90 01 03 06 17 59 11 04 58 08 6f 90 01 03 06 17 59 11 05 58 73 90 01 03 06 a2 00 11 05 17 58 13 05 11 05 19 fe 04 13 06 11 06 2d c9 90 00 } //10
		$a_81_1 = {42 61 74 74 6c 65 53 68 69 70 } //1 BattleShip
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=12
 
}
rule Trojan_BAT_AgentTesla_EH_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {50 00 6f 00 72 00 61 00 6c 00 50 00 65 00 72 00 69 00 6c 00 5f 00 53 00 74 00 65 00 66 00 61 00 6e 00 54 00 69 00 63 00 75 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 PoralPeril_StefanTicu.Resources
		$a_01_1 = {47 00 6f 00 6f 00 67 00 6c 00 65 00 43 00 68 00 72 00 6f 00 6d 00 65 00 53 00 74 00 61 00 74 00 75 00 73 00 } //1 GoogleChromeStatus
		$a_01_2 = {79 00 6b 00 68 00 67 00 33 00 79 00 75 00 7a 00 71 00 38 00 39 00 33 00 31 00 } //1 ykhg3yuzq8931
		$a_01_3 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //1 DebuggerStepThroughAttribute
		$a_01_4 = {48 69 64 65 4d 6f 64 75 6c 65 4e 61 6d 65 41 74 74 72 69 62 75 74 65 } //1 HideModuleNameAttribute
		$a_01_5 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Trojan_BAT_AgentTesla_EH_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_01_0 = {fa 01 33 00 16 00 00 01 00 00 00 93 00 00 00 1f 00 00 00 98 00 00 00 86 00 00 00 75 } //2
		$a_01_1 = {59 00 6f 00 75 00 72 00 5f 00 46 00 72 00 69 00 65 00 6e 00 64 00 5f 00 54 00 68 00 65 00 5f 00 52 00 61 00 74 00 5f 00 69 00 63 00 6f 00 6e 00 } //1 Your_Friend_The_Rat_icon
		$a_01_2 = {4b 00 72 00 75 00 73 00 6b 00 61 00 6c 00 20 00 41 00 6c 00 67 00 6f 00 72 00 69 00 74 00 68 00 6d 00 } //1 Kruskal Algorithm
		$a_01_3 = {73 00 6d 00 74 00 70 00 2e 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00 } //1 smtp.gmail.com
		$a_01_4 = {72 00 75 00 6e 00 6f 00 6e 00 73 00 74 00 61 00 72 00 74 00 3d 00 } //1 runonstart=
		$a_01_5 = {44 00 65 00 62 00 75 00 67 00 4c 00 6f 00 67 00 2e 00 74 00 78 00 74 00 } //1 DebugLog.txt
		$a_01_6 = {43 00 61 00 6c 00 6c 00 4c 00 6f 00 67 00 5f 00 } //1 CallLog_
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=8
 
}
rule Trojan_BAT_AgentTesla_EH_MTB_5{
	meta:
		description = "Trojan:BAT/AgentTesla.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {48 00 61 00 64 00 5a 00 4b 00 38 00 50 00 4e 00 42 00 6e 00 47 00 70 00 45 00 71 00 66 00 45 00 45 00 32 00 2e 00 32 00 34 00 6f 00 43 00 4b 00 33 00 30 00 69 00 69 00 4b 00 69 00 4a 00 5a 00 4c 00 67 00 76 00 6e 00 62 00 } //1 HadZK8PNBnGpEqfEE2.24oCK30iiKiJZLgvnb
		$a_01_1 = {69 00 67 00 6e 00 6f 00 72 00 65 00 70 00 61 00 72 00 74 00 69 00 61 00 6c 00 6c 00 79 00 65 00 6d 00 70 00 74 00 79 00 64 00 61 00 74 00 61 00 } //1 ignorepartiallyemptydata
		$a_01_2 = {73 00 74 00 65 00 61 00 6c 00 65 00 72 00 } //1 stealer
		$a_01_3 = {73 00 65 00 74 00 20 00 43 00 44 00 41 00 75 00 64 00 69 00 6f 00 20 00 64 00 6f 00 6f 00 72 00 20 00 6f 00 70 00 65 00 6e 00 } //1 set CDAudio door open
		$a_01_4 = {41 65 73 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 AesCryptoServiceProvider
		$a_01_5 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Trojan_BAT_AgentTesla_EH_MTB_6{
	meta:
		description = "Trojan:BAT/AgentTesla.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,26 00 26 00 0b 00 00 "
		
	strings :
		$a_81_0 = {24 33 63 64 39 66 34 36 30 2d 39 33 65 65 2d 34 39 65 39 2d 38 66 32 66 2d 32 32 65 63 62 30 39 31 38 66 63 39 } //20 $3cd9f460-93ee-49e9-8f2f-22ecb0918fc9
		$a_81_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //5 CreateInstance
		$a_81_2 = {41 63 74 69 76 61 74 6f 72 } //5 Activator
		$a_81_3 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_4 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_81_5 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //1 DebuggerStepThroughAttribute
		$a_81_6 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_7 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_81_8 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_9 = {44 61 74 61 44 72 61 67 6f 6e 55 72 6c } //1 DataDragonUrl
		$a_81_10 = {43 68 61 6d 70 69 6f 6e 47 47 55 72 6c } //1 ChampionGGUrl
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*5+(#a_81_2  & 1)*5+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1) >=38
 
}
rule Trojan_BAT_AgentTesla_EH_MTB_7{
	meta:
		description = "Trojan:BAT/AgentTesla.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {35 00 6e 00 71 00 52 00 4e 00 66 00 74 00 70 00 65 00 43 00 49 00 48 00 52 00 45 00 33 00 4e 00 4d 00 78 00 2e 00 49 00 6a 00 56 00 74 00 51 00 64 00 69 00 48 00 75 00 37 00 45 00 62 00 47 00 4d 00 76 00 72 00 37 00 4e 00 } //1 5nqRNftpeCIHRE3NMx.IjVtQdiHu7EbGMvr7N
		$a_01_1 = {4f 00 6e 00 53 00 74 00 65 00 61 00 6c 00 65 00 72 00 44 00 6f 00 6e 00 65 00 } //1 OnStealerDone
		$a_01_2 = {5b 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 73 00 5d 00 20 00 47 00 72 00 61 00 62 00 62 00 69 00 6e 00 67 00 20 00 63 00 6f 00 6f 00 6b 00 69 00 65 00 73 00 } //1 [Browsers] Grabbing cookies
		$a_01_3 = {5b 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 73 00 5d 00 20 00 47 00 72 00 61 00 62 00 62 00 69 00 6e 00 67 00 20 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 73 00 } //1 [Browsers] Grabbing passwords
		$a_01_4 = {5b 00 53 00 74 00 65 00 61 00 6c 00 65 00 72 00 50 00 6c 00 75 00 67 00 69 00 6e 00 5d 00 20 00 49 00 6e 00 76 00 6f 00 6b 00 65 00 } //1 [StealerPlugin] Invoke
		$a_01_5 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 74 00 6e 00 } //1 schtasks.exe /create /tn
		$a_01_6 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 46 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 } //1 SELECT * FROM FirewallProduct
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}