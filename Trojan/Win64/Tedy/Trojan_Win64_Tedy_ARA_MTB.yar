
rule Trojan_Win64_Tedy_ARA_MTB{
	meta:
		description = "Trojan:Win64/Tedy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b7 54 45 40 48 8b 85 ?? ?? ?? ?? 66 89 94 45 f0 02 00 00 48 83 85 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win64_Tedy_ARA_MTB_2{
	meta:
		description = "Trojan:Win64/Tedy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 55 10 48 8b 45 f8 48 01 d0 0f b6 00 48 8b 4d 10 48 8b 55 f8 48 01 ca 32 45 f7 88 02 48 83 45 f8 01 48 8b 45 f8 48 3b 45 18 72 d3 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_Win64_Tedy_ARA_MTB_3{
	meta:
		description = "Trojan:Win64/Tedy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 75 72 6c 20 2d 46 20 22 69 6d 61 67 65 3d 40 } //2 curl -F "image=@
		$a_01_1 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 2e 77 69 6e 53 65 73 73 69 6f 6e } //2 \Microsoft\Windows\.winSession
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
rule Trojan_Win64_Tedy_ARA_MTB_4{
	meta:
		description = "Trojan:Win64/Tedy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 53 74 61 72 74 75 70 5c 4e 56 49 44 49 41 47 72 61 70 68 69 63 73 2e 6c 6e 6b } //2 \Startup\NVIDIAGraphics.lnk
		$a_01_1 = {5c 53 74 61 72 74 75 70 5c 4d 69 63 72 6f 73 6f 66 74 44 65 66 65 6e 64 65 72 2e 6c 6e 6b } //2 \Startup\MicrosoftDefender.lnk
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
rule Trojan_Win64_Tedy_ARA_MTB_5{
	meta:
		description = "Trojan:Win64/Tedy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 65 74 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 44 69 73 61 62 6c 65 52 65 61 6c 74 69 6d 65 4d 6f 6e 69 74 6f 72 69 6e 67 20 24 74 72 75 65 20 2d 44 69 73 61 62 6c 65 53 63 72 69 70 74 53 63 61 6e 6e 69 6e 67 20 24 74 72 75 65 } //1 Set-MpPreference -DisableRealtimeMonitoring $true -DisableScriptScanning $true
		$a_01_1 = {2d 44 69 73 61 62 6c 65 42 65 68 61 76 69 6f 72 4d 6f 6e 69 74 6f 72 69 6e 67 20 24 74 72 75 65 20 2d 44 69 73 61 62 6c 65 49 4f 41 56 50 72 6f 74 65 63 74 69 6f 6e 20 24 74 72 75 65 20 2d 44 69 73 61 62 6c 65 49 6e 74 72 75 73 69 6f 6e 50 72 65 76 65 6e 74 69 6f 6e 53 79 73 74 65 6d 20 24 74 72 75 65 } //1 -DisableBehaviorMonitoring $true -DisableIOAVProtection $true -DisableIntrusionPreventionSystem $true
		$a_01_2 = {41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 } //1 Add-MpPreference -ExclusionPath
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}