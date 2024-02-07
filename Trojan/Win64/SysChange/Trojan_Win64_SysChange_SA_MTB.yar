
rule Trojan_Win64_SysChange_SA_MTB{
	meta:
		description = "Trojan:Win64/SysChange.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {48 00 69 00 64 00 65 00 49 00 63 00 6f 00 6e 00 73 00 } //01 00  HideIcons
		$a_01_1 = {77 69 6e 6c 6f 63 6b 5c 6c 63 6b 5c 6c 63 6b 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 6c 63 6b 2e 70 64 62 } //01 00  winlock\lck\lck\x64\Release\lck.pdb
		$a_00_2 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 54 00 61 00 73 00 6b 00 4d 00 67 00 72 00 } //01 00  DisableTaskMgr
		$a_00_3 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 43 00 68 00 61 00 6e 00 67 00 65 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 } //01 00  DisableChangePassword
		$a_00_4 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 4c 00 6f 00 63 00 6b 00 57 00 6f 00 72 00 6b 00 73 00 74 00 61 00 74 00 69 00 6f 00 6e 00 } //01 00  DisableLockWorkstation
		$a_00_5 = {43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 50 00 6f 00 6c 00 69 00 63 00 69 00 65 00 73 00 5c 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 20 00 48 00 69 00 64 00 64 00 65 00 6e 00 } //01 00  CurrentVersion\Policies\Explorer Hidden
		$a_00_6 = {45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5c 00 48 00 69 00 64 00 65 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 49 00 63 00 6f 00 6e 00 73 00 5c 00 4e 00 65 00 77 00 53 00 74 00 61 00 72 00 74 00 50 00 61 00 6e 00 65 00 } //00 00  Explorer\HideDesktopIcons\NewStartPane
	condition:
		any of ($a_*)
 
}