
rule VirTool_BAT_CryptInject_PD_MTB{
	meta:
		description = "VirTool:BAT/CryptInject.PD!MTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {41 6e 74 69 54 61 73 6b 4d 61 6e 61 67 65 72 4b 69 6c 6c } //1 AntiTaskManagerKill
		$a_01_1 = {73 76 63 68 6f 73 74 2e 65 78 65 } //1 svchost.exe
		$a_01_2 = {24 36 31 31 30 36 39 32 65 2d 66 35 33 32 2d 34 63 36 39 2d 38 37 35 31 2d 32 37 66 39 62 34 64 33 66 61 36 65 } //1 $6110692e-f532-4c69-8751-27f9b4d3fa6e
		$a_01_3 = {73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 svchost.Resources
		$a_01_4 = {47 65 74 50 72 6f 63 65 73 73 65 73 42 79 4e 61 6d 65 } //1 GetProcessesByName
		$a_01_5 = {67 65 74 5f 46 69 6c 65 4e 61 6d 65 } //1 get_FileName
		$a_01_6 = {76 32 2e 30 2e 35 30 37 32 37 } //1 v2.0.50727
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}