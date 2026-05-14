
rule Trojan_Win32_KillWin_ARR_MTB{
	meta:
		description = "Trojan:Win32/KillWin.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_03_0 = {41 0f 45 d5 0b 54 31 ?? 0b d7 83 e2 17 } //2
		$a_01_1 = {54 41 53 4b 52 4f 55 54 49 4e 45 5f 44 49 53 41 42 4c 45 5f 52 45 47 49 53 54 52 59 } //12 TASKROUTINE_DISABLE_REGISTRY
		$a_01_2 = {52 65 67 69 73 74 72 79 20 6c 6f 67 67 69 6e 67 20 69 73 20 44 49 53 41 42 4c 45 44 20 28 54 41 53 4b 52 4f 55 54 49 4e 45 5f 44 49 53 41 42 4c 45 5f 52 45 47 49 53 54 52 59 3d 31 29 } //6 Registry logging is DISABLED (TASKROUTINE_DISABLE_REGISTRY=1)
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*12+(#a_01_2  & 1)*6) >=20
 
}
rule Trojan_Win32_KillWin_ARR_MTB_2{
	meta:
		description = "Trojan:Win32/KillWin.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_81_0 = {49 66 20 79 6f 75 20 65 78 65 63 75 74 65 20 74 68 69 73 20 6d 61 6c 77 61 72 65 20 61 6e 64 20 6c 6f 73 65 20 79 6f 75 72 20 64 61 74 61 2c 20 74 68 65 20 70 72 6f 64 75 63 65 72 20 77 69 6c 6c 20 6e 6f 74 20 62 65 20 72 65 73 70 6f 6e 73 69 62 6c 65 21 } //2 If you execute this malware and lose your data, the producer will not be responsible!
		$a_81_1 = {64 65 6c 20 2f 66 20 2f 73 20 2f 71 20 43 3a 5c 62 6f 6f 74 6d 67 72 } //8 del /f /s /q C:\bootmgr
		$a_81_2 = {64 69 73 6b 70 61 72 74 20 2f 73 20 22 31 2e 74 78 74 22 } //10 diskpart /s "1.txt"
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*8+(#a_81_2  & 1)*10) >=20
 
}