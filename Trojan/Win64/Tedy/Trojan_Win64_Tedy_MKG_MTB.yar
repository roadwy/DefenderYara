
rule Trojan_Win64_Tedy_MKG_MTB{
	meta:
		description = "Trojan:Win64/Tedy.MKG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 63 68 74 61 73 6b 73 20 2f 44 65 6c 65 74 65 20 2f 54 4e 20 22 41 63 63 22 20 2f 46 20 3e 6e 75 6c 20 32 3e 26 31 } //20 schtasks /Delete /TN "Acc" /F >nul 2>&1
		$a_01_1 = {73 63 68 74 61 73 6b 73 20 2f 43 72 65 61 74 65 20 2f 54 4e 20 22 41 63 63 22 20 2f 53 43 20 4f 4e 4c 4f 47 4f 4e 20 2f 52 55 20 22 49 4e 54 45 52 41 43 54 49 56 45 22 20 2f 52 4c 20 48 49 47 48 45 53 54 20 2f 54 52 20 22 43 3a 5c 41 63 63 2e 65 78 65 22 20 2f 46 20 3e 6e 75 6c 20 32 3e 26 31 } //15 schtasks /Create /TN "Acc" /SC ONLOGON /RU "INTERACTIVE" /RL HIGHEST /TR "C:\Acc.exe" /F >nul 2>&1
		$a_01_2 = {73 63 68 74 61 73 6b 73 20 2f 43 72 65 61 74 65 20 2f 54 4e 20 22 41 63 63 22 20 2f 53 43 20 4f 4e 53 54 41 52 54 20 2f 52 55 20 53 59 53 54 45 4d 20 2f 52 4c 20 48 49 47 48 45 53 54 20 2f 54 52 20 22 43 3a 5c 41 63 63 2e 65 78 65 22 20 2f 46 20 3e 6e 75 6c 20 32 3e 26 31 } //15 schtasks /Create /TN "Acc" /SC ONSTART /RU SYSTEM /RL HIGHEST /TR "C:\Acc.exe" /F >nul 2>&1
		$a_01_3 = {73 63 20 64 65 6c 65 74 65 20 41 63 63 20 3e 6e 75 6c 20 32 3e 26 31 } //10 sc delete Acc >nul 2>&1
		$a_01_4 = {73 63 20 64 65 6c 65 74 65 20 61 63 63 20 3e 6e 75 6c 20 32 3e 26 31 } //10 sc delete acc >nul 2>&1
		$a_81_5 = {31 4e 56 48 44 41 30 30 31 } //5 1NVHDA001
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*15+(#a_01_2  & 1)*15+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_81_5  & 1)*5) >=50
 
}