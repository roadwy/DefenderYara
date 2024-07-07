
rule Trojan_Win32_Diztakun_AR_MTB{
	meta:
		description = "Trojan:Win32/Diztakun.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //10 taskkill /f /im explorer.exe
		$a_01_1 = {5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d 20 2f 76 20 44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 31 20 2f 66 } //5 \Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableTaskMgr /t REG_DWORD /d 1 /f
		$a_01_2 = {65 63 68 6f 20 43 4f 52 4f 4e 41 56 49 52 55 53 } //10 echo CORONAVIRUS
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*10) >=25
 
}