
rule PWS_Win32_Frethog_gen_B{
	meta:
		description = "PWS:Win32/Frethog.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,6b 00 6b 00 12 00 00 "
		
	strings :
		$a_00_0 = {46 6f 72 74 68 67 6f 65 72 } //50 Forthgoer
		$a_01_1 = {4c 61 54 61 6c 65 43 6c 69 65 6e 74 2e 65 78 65 } //50 LaTaleClient.exe
		$a_00_2 = {67 61 6d 65 63 6c 69 65 6e 74 2e 65 78 65 } //50 gameclient.exe
		$a_01_3 = {53 75 6e 67 61 6d 65 2e 65 78 65 } //50 Sungame.exe
		$a_01_4 = {45 6c 65 6d 65 6e 74 43 6c 69 65 6e 74 2e 65 78 65 } //50 ElementClient.exe
		$a_01_5 = {70 61 74 63 68 75 70 64 61 74 65 2e 65 78 65 } //50 patchupdate.exe
		$a_01_6 = {63 61 62 61 6c 6d 61 69 6e 2e 65 78 65 } //50 cabalmain.exe
		$a_00_7 = {41 64 6a 75 73 74 54 6f 6b 65 6e 50 72 69 76 69 6c 65 67 65 73 } //1 AdjustTokenPrivileges
		$a_00_8 = {4c 6f 6f 6b 75 70 50 72 69 76 69 6c 65 67 65 56 61 6c 75 65 41 } //1 LookupPrivilegeValueA
		$a_01_9 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //1 GetCurrentProcess
		$a_00_10 = {4f 70 65 6e 50 72 6f 63 65 73 73 54 6f 6b 65 6e } //1 OpenProcessToken
		$a_01_11 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //1 SeDebugPrivilege
		$a_01_12 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_13 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //1 InternetReadFile
		$a_01_14 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //1 InternetOpenUrlA
		$a_01_15 = {54 68 75 6e 64 65 72 53 6d 61 72 74 4c 69 6d 69 74 65 72 2e 65 78 65 } //-500 ThunderSmartLimiter.exe
		$a_01_16 = {5c 4f 76 65 72 57 6f 6c 66 2e 43 6c 69 65 6e 74 2e 42 4c 5c 6f 62 6a 5c 78 38 36 5c 52 65 6c 65 61 73 65 5c 4f 76 65 72 57 6f 6c 66 2e 43 6c 69 65 6e 74 2e 42 4c 2e 70 64 62 } //-500 \OverWolf.Client.BL\obj\x86\Release\OverWolf.Client.BL.pdb
		$a_01_17 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4f 00 76 00 65 00 72 00 77 00 6f 00 6c 00 66 00 5c 00 } //-500 Software\Overwolf\
	condition:
		((#a_00_0  & 1)*50+(#a_01_1  & 1)*50+(#a_00_2  & 1)*50+(#a_01_3  & 1)*50+(#a_01_4  & 1)*50+(#a_01_5  & 1)*50+(#a_01_6  & 1)*50+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_01_9  & 1)*1+(#a_00_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*-500+(#a_01_16  & 1)*-500+(#a_01_17  & 1)*-500) >=107
 
}