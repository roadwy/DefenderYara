
rule Trojan_Win32_ProcKiller_B_MTB{
	meta:
		description = "Trojan:Win32/ProcKiller.B!MTB,SIGNATURE_TYPE_PEHSTR,04 00 03 00 07 00 00 "
		
	strings :
		$a_01_0 = {69 44 65 74 65 63 74 5f 56 49 50 2e 62 61 74 } //1 iDetect_VIP.bat
		$a_01_1 = {62 00 32 00 65 00 69 00 6e 00 63 00 66 00 69 00 6c 00 65 00 63 00 6f 00 75 00 6e 00 74 00 } //1 b2eincfilecount
		$a_01_2 = {72 75 6e 64 6c 6c 33 32 20 55 53 45 52 33 32 2e 44 4c 4c 2c 53 77 61 70 4d 6f 75 73 65 42 75 74 74 6f 6e } //1 rundll32 USER32.DLL,SwapMouseButton
		$a_01_3 = {50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d 20 2f 76 20 44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 20 2f 74 20 52 45 47 5f 53 5a 20 2f 64 20 31 20 2f 66 } //1 Policies\System /v DisableTaskMgr /t REG_SZ /d 1 /f
		$a_01_4 = {6e 65 74 20 73 74 6f 70 20 57 69 6e 44 65 66 65 6e 64 } //1 net stop WinDefend
		$a_01_5 = {4c 65 61 6b 20 62 79 20 24 68 61 74 72 61 } //1 Leak by $hatra
		$a_01_6 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 74 20 2f 69 6d 20 46 69 72 65 77 61 6c 6c 43 6f 6e 74 72 6f 6c 50 61 6e 65 6c 2e 65 78 65 } //1 taskkill /f /t /im FirewallControlPanel.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=3
 
}