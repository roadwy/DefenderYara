
rule Trojan_Win32_Simeda_A{
	meta:
		description = "Trojan:Win32/Simeda.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec 4c 53 56 57 b9 05 00 00 00 be ?? ?? ?? ?? 8d 7d ec f3 a5 a1 ?? ?? ?? ?? 89 45 dc 8b 0d ?? ?? ?? ?? 89 4d e0 8b 15 ?? ?? ?? ?? 89 55 e4 a0 ?? ?? ?? ?? 88 45 e8 8d 4d ec 51 ff 15 } //1
		$a_00_1 = {4e 61 74 69 61 6f 6e 61 6c 20 53 61 66 65 20 4d 65 61 64 69 } //1 Natiaonal Safe Meadi
		$a_00_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 72 75 6e 64 6c 6c 33 32 2e 65 78 65 } //1 taskkill /f /im rundll32.exe
		$a_00_3 = {61 50 50 4c 49 43 41 54 49 4f 4e 53 5c 49 45 58 50 4c 4f 52 45 2e 45 58 45 5c 53 48 45 4c 4c 5c 4f 50 45 4e 5c 43 4f 4d 4d 41 4e 44 } //1 aPPLICATIONS\IEXPLORE.EXE\SHELL\OPEN\COMMAND
		$a_02_4 = {4e 65 74 42 6f 74 5f 41 74 74 61 63 6b [0-04] 5c 53 65 72 76 65 72 5c 73 76 63 68 6f 73 74 5c 52 65 6c 65 61 73 65 5c 33 36 35 43 6b 6a 78 2e 70 64 62 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1) >=4
 
}