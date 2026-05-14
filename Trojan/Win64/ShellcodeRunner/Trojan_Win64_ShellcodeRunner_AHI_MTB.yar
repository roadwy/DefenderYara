
rule Trojan_Win64_ShellcodeRunner_AHI_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.AHI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 04 00 00 "
		
	strings :
		$a_01_0 = {47 6c 6f 62 61 6c 5c 4d 61 69 6e 50 72 6f 67 72 61 6d 4d 75 74 65 78 } //10 Global\MainProgramMutex
		$a_01_1 = {47 6c 6f 62 61 6c 5c 47 75 61 72 64 69 61 6e 4d 75 74 65 78 } //20 Global\GuardianMutex
		$a_01_2 = {45 78 65 63 75 74 65 53 68 65 6c 6c 63 6f 64 65 } //30 ExecuteShellcode
		$a_01_3 = {73 63 68 74 61 73 6b 73 20 2f 43 72 65 61 74 65 20 2f 54 4e 20 22 53 79 73 74 65 6d 53 65 72 76 69 63 65 22 20 2f 54 52 20 22 5c 22 25 73 5c 22 22 20 2f 53 43 20 4f 4e 4c 4f 47 4f 4e 20 2f 52 4c 20 48 49 47 48 45 53 54 20 2f 52 55 20 22 25 73 22 20 2f 46 } //40 schtasks /Create /TN "SystemService" /TR "\"%s\"" /SC ONLOGON /RL HIGHEST /RU "%s" /F
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*20+(#a_01_2  & 1)*30+(#a_01_3  & 1)*40) >=100
 
}