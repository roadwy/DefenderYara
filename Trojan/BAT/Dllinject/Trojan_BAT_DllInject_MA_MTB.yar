
rule Trojan_BAT_DllInject_MA_MTB{
	meta:
		description = "Trojan:BAT/DllInject.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {07 08 9a 0d 00 09 6f 90 01 03 0a 72 0b 00 00 70 28 90 01 03 0a 13 04 11 04 13 05 11 05 2c 09 00 09 90 00 } //5
		$a_01_1 = {4c 61 75 6e 63 68 45 78 70 6c 6f 69 74 } //1 LaunchExploit
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //1 DownloadString
		$a_01_3 = {52 6f 62 6c 6f 78 5f 45 78 65 63 75 74 6f 72 5f 57 6f 6c 66 43 68 65 61 74 73 2e 50 72 6f 70 65 72 74 69 65 73 } //1 Roblox_Executor_WolfCheats.Properties
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}
rule Trojan_BAT_DllInject_MA_MTB_2{
	meta:
		description = "Trojan:BAT/DllInject.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 95 a2 21 09 03 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 51 00 00 00 08 00 00 00 2d 00 00 00 1d 00 00 00 1f } //5
		$a_01_1 = {4f 72 61 6e 67 65 5f 54 65 63 68 2e 50 72 6f 70 65 72 74 69 65 73 } //1 Orange_Tech.Properties
		$a_01_2 = {32 62 63 37 66 33 38 37 2d 66 62 62 66 2d 34 31 61 31 2d 39 39 37 34 2d 36 36 62 37 31 66 33 31 66 37 37 36 } //1 2bc7f387-fbbf-41a1-9974-66b71f31f776
		$a_01_3 = {4c 61 75 6e 63 68 45 78 70 6c 6f 69 74 } //1 LaunchExploit
		$a_01_4 = {73 63 72 69 70 74 73 5f 4c 6f 61 64 } //1 scripts_Load
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}