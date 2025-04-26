
rule Trojan_Win64_Turla_AG_MSR{
	meta:
		description = "Trojan:Win64/Turla.AG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 3a 5c 72 75 73 74 70 72 6f 6a 65 63 74 5c 73 68 65 6c 6c 63 6f 64 65 5c 30 32 2d 65 63 77 5c 74 61 72 67 65 74 5c 72 65 6c 65 61 73 65 5c 64 65 70 73 5c 59 69 68 73 69 77 65 69 2e 70 64 62 } //2 D:\rustproject\shellcode\02-ecw\target\release\deps\Yihsiwei.pdb
		$a_01_1 = {66 7a 34 38 38 33 65 34 66 79 65 38 7a 38 79 79 79 79 79 79 34 31 35 31 34 31 35 79 35 32 35 31 35 36 34 38 33 31 64 32 36 35 34 38 38 62 35 32 36 79 34 38 38 62 35 32 31 38 34 } //2 fz4883e4fye8z8yyyyyy4151415y5251564831d265488b526y488b52184
		$a_01_2 = {47 65 74 45 6e 76 69 72 6f 6e 6d 65 6e 74 56 61 72 69 61 62 6c 65 57 } //1 GetEnvironmentVariableW
		$a_01_3 = {57 72 69 74 65 43 6f 6e 73 6f 6c 65 57 } //1 WriteConsoleW
		$a_01_4 = {57 72 69 74 65 46 69 6c 65 } //1 WriteFile
		$a_01_5 = {47 65 74 54 65 6d 70 50 61 74 68 32 57 } //1 GetTempPath2W
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}