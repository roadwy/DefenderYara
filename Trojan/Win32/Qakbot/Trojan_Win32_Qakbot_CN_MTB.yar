
rule Trojan_Win32_Qakbot_CN_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.CN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_01_0 = {49 4c 4c 46 6f 72 63 65 55 70 64 61 74 65 43 68 65 63 6b } //1 ILLForceUpdateCheck
		$a_01_1 = {49 4c 4c 47 65 74 4f 70 74 69 6f 6e 61 6c 50 61 72 61 6d } //1 ILLGetOptionalParam
		$a_01_2 = {49 4c 4c 4f 6e 41 70 70 6c 69 63 61 74 69 6f 6e 53 74 61 72 74 75 70 } //1 ILLOnApplicationStartup
		$a_01_3 = {49 4c 4c 4f 6e 41 70 70 6c 69 63 61 74 69 6f 6e 55 6e 69 6e 73 74 61 6c 6c } //1 ILLOnApplicationUninstall
		$a_01_4 = {49 4c 4c 53 65 74 45 78 65 63 75 74 6f 72 50 61 74 68 } //1 ILLSetExecutorPath
		$a_01_5 = {4d 6f 74 64 } //1 Motd
		$a_01_6 = {49 4c 4c 44 6f 77 6e 6c 6f 61 64 41 6e 64 49 6e 73 74 61 6c 6c 53 69 6c 65 6e 74 55 70 64 61 74 65 } //1 ILLDownloadAndInstallSilentUpdate
		$a_01_7 = {49 4c 4c 47 65 74 55 6e 69 71 55 73 65 72 49 64 } //1 ILLGetUniqUserId
		$a_01_8 = {49 4c 4c 49 73 55 70 64 61 74 65 41 76 61 69 6c 61 62 6c 65 } //1 ILLIsUpdateAvailable
		$a_01_9 = {49 4c 4c 53 65 74 55 6e 69 71 75 65 50 61 72 61 6d } //1 ILLSetUniqueParam
		$a_01_10 = {49 4c 4c 53 65 74 55 70 64 61 74 65 44 65 73 74 69 6e 61 74 69 6f 6e } //1 ILLSetUpdateDestination
		$a_01_11 = {49 4c 4c 49 73 55 70 67 72 61 64 65 41 76 61 69 6c 61 62 6c 65 } //1 ILLIsUpgradeAvailable
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=12
 
}