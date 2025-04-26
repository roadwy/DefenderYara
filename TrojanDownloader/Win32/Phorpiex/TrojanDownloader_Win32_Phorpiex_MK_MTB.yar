
rule TrojanDownloader_Win32_Phorpiex_MK_MTB{
	meta:
		description = "TrojanDownloader:Win32/Phorpiex.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 0f 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 3a 2f 2f 32 31 37 2e 38 2e 31 31 37 2e 36 33 2f 73 70 6d } //http://217.8.117.63/spm  10
		$a_80_1 = {68 74 74 70 3a 2f 2f 74 6c 64 72 6e 65 74 2e 74 6f 70 2f 73 70 6d } //http://tldrnet.top/spm  10
		$a_80_2 = {44 69 73 61 62 6c 65 53 63 61 6e 4f 6e 52 65 61 6c 74 69 6d 65 45 6e 61 62 6c 65 } //DisableScanOnRealtimeEnable  1
		$a_80_3 = {44 69 73 61 62 6c 65 4f 6e 41 63 63 65 73 73 50 72 6f 74 65 63 74 69 6f 6e } //DisableOnAccessProtection  1
		$a_80_4 = {44 69 73 61 62 6c 65 42 65 68 61 76 69 6f 72 4d 6f 6e 69 74 6f 72 69 6e 67 } //DisableBehaviorMonitoring  1
		$a_80_5 = {41 6e 74 69 56 69 72 75 73 4f 76 65 72 72 69 64 65 } //AntiVirusOverride  1
		$a_80_6 = {55 70 64 61 74 65 73 4f 76 65 72 72 69 64 65 } //UpdatesOverride  1
		$a_80_7 = {46 69 72 65 77 61 6c 6c 4f 76 65 72 72 69 64 65 } //FirewallOverride  1
		$a_80_8 = {41 6e 74 69 56 69 72 75 73 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 } //AntiVirusDisableNotify  1
		$a_80_9 = {55 70 64 61 74 65 73 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 } //UpdatesDisableNotify  1
		$a_80_10 = {41 75 74 6f 55 70 64 61 74 65 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 } //AutoUpdateDisableNotify  1
		$a_80_11 = {46 69 72 65 77 61 6c 6c 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 } //FirewallDisableNotify  1
		$a_80_12 = {44 69 73 61 62 6c 65 41 6e 74 69 53 70 79 77 61 72 65 } //DisableAntiSpyware  1
		$a_80_13 = {53 4f 46 54 57 41 52 45 5c 50 6f 6c 69 63 69 65 73 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 5c 52 65 61 6c 2d 54 69 6d 65 20 50 72 6f 74 65 63 74 69 6f 6e } //SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection  2
		$a_80_14 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 53 68 61 72 65 64 41 63 63 65 73 73 5c 50 61 72 61 6d 65 74 65 72 73 5c 46 69 72 65 77 61 6c 6c 50 6f 6c 69 63 79 5c 53 74 61 6e 64 61 72 64 50 72 6f 66 69 6c 65 5c 41 75 74 68 6f 72 69 7a 65 64 41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 4c 69 73 74 } //SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\AuthorizedApplications\List  2
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*10+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1+(#a_80_13  & 1)*2+(#a_80_14  & 1)*2) >=25
 
}