
rule Trojan_Win64_AntiVm_NE_MTB{
	meta:
		description = "Trojan:Win64/AntiVm.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_81_0 = {63 6f 73 69 74 61 73 2e 70 64 62 } //4 cositas.pdb
		$a_81_1 = {74 61 73 6b 6b 69 6c 6c 2f 49 4d 2e 65 78 65 } //1 taskkill/IM.exe
		$a_81_2 = {2f 43 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 } //1 /C-ExclusionPathAdd-MpPreference
		$a_81_3 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 63 6d 64 2e 65 78 65 50 72 6f 63 65 73 73 54 72 61 63 6b 65 72 2e 65 78 65 57 69 6e 64 6f 77 73 44 65 66 65 6e 64 65 72 2e 65 78 65 73 74 61 72 74 } //1 powershell.execmd.exeProcessTracker.exeWindowsDefender.exestart
		$a_81_4 = {72 65 67 61 64 64 48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d 2f 76 43 6f 6e 73 65 6e 74 50 72 6f 6d 70 74 42 65 68 61 76 69 6f 72 41 64 6d 69 6e } //1 regaddHKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System/vConsentPromptBehaviorAdmin
	condition:
		((#a_81_0  & 1)*4+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=8
 
}