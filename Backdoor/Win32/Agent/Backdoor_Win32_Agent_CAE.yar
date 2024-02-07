
rule Backdoor_Win32_Agent_CAE{
	meta:
		description = "Backdoor:Win32/Agent.CAE,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 53 4b 5f 53 65 72 76 65 72 5f 44 6c 6c } //01 00  ESK_Server_Dll
		$a_01_1 = {5f 44 65 6c 65 74 65 2e 64 6c 6c 00 4c 65 73 73 } //01 00 
		$a_01_2 = {52 65 6c 6f 61 64 20 55 73 65 72 20 50 61 74 68 20 43 6f 6e 66 69 67 20 46 69 6c 65 } //01 00  Reload User Path Config File
		$a_01_3 = {4d 61 6e 67 2e 78 6d 6c } //01 00  Mang.xml
		$a_01_4 = {54 69 6d 65 6f 75 74 20 26 20 51 55 49 54 21 21 21 } //01 00  Timeout & QUIT!!!
		$a_01_5 = {55 00 6e 00 69 00 63 00 6f 00 64 00 65 00 20 00 4e 00 6f 00 72 00 6d 00 61 00 6c 00 69 00 7a 00 61 00 74 00 69 00 6f 00 6e 00 20 00 44 00 4c 00 4c 00 } //00 00  Unicode Normalization DLL
		$a_00_6 = {5d 04 00 00 } //47 b6 
	condition:
		any of ($a_*)
 
}