
rule Trojan_Win64_Zusy_EM_MTB{
	meta:
		description = "Trojan:Win64/Zusy.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 8b 40 04 41 03 c2 48 98 48 8d 0c 40 41 8b 00 41 03 c3 49 83 c0 08 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win64_Zusy_EM_MTB_2{
	meta:
		description = "Trojan:Win64/Zusy.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {47 00 61 00 6d 00 65 00 20 00 52 00 65 00 70 00 61 00 63 00 6b 00 20 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 } //1 Game Repack Install
		$a_01_1 = {2e 74 68 65 6d 69 64 61 00 a0 73 00 00 60 15 00 00 00 00 00 00 b2 0c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win64_Zusy_EM_MTB_3{
	meta:
		description = "Trojan:Win64/Zusy.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {6a 50 61 33 68 70 7a 42 76 71 } //1 jPa3hpzBvq
		$a_81_1 = {44 69 73 63 6f 72 64 20 44 4d 20 3a 20 5f 65 6e 63 72 79 70 74 33 64 2e } //1 Discord DM : _encrypt3d.
		$a_81_2 = {5c 53 74 61 72 48 69 67 68 53 72 63 46 69 78 56 33 5c 42 6c 75 65 20 6c 6f 61 64 65 72 5c 42 6c 75 65 20 6c 6f 61 64 65 72 } //1 \StarHighSrcFixV3\Blue loader\Blue loader
		$a_81_3 = {53 74 61 72 5f 48 69 67 68 } //1 Star_High
		$a_81_4 = {70 32 6a 31 72 61 63 } //1 p2j1rac
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule Trojan_Win64_Zusy_EM_MTB_4{
	meta:
		description = "Trojan:Win64/Zusy.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {49 20 46 6f 6c 6c 6f 77 20 59 6f 75 2e 64 6c 6c } //1 I Follow You.dll
		$a_81_1 = {49 5f 46 6f 6c 6c 6f 77 5f 59 6f 75 5f 61 75 6a 64 61 77 } //1 I_Follow_You_aujdaw
		$a_81_2 = {47 65 74 54 65 6d 70 50 61 74 68 41 } //1 GetTempPathA
		$a_81_3 = {43 6f 70 79 46 69 6c 65 41 } //1 CopyFileA
		$a_81_4 = {57 69 6e 45 78 65 63 } //1 WinExec
		$a_81_5 = {57 69 6e 48 74 74 70 52 65 63 65 69 76 65 52 65 73 70 6f 6e 73 65 } //1 WinHttpReceiveResponse
		$a_81_6 = {63 65 69 6c 66 } //1 ceilf
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}
rule Trojan_Win64_Zusy_EM_MTB_5{
	meta:
		description = "Trojan:Win64/Zusy.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {44 3a 5c 44 65 73 6b 74 6f 70 5c 54 68 65 44 4c 4c 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 54 68 65 44 4c 4c 2e 70 64 62 } //1 D:\Desktop\TheDLL\x64\Release\TheDLL.pdb
		$a_81_1 = {4a 4c 49 5f 49 6e 69 74 41 72 67 50 72 6f 63 65 73 73 69 6e 67 } //1 JLI_InitArgProcessing
		$a_81_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 57 } //1 URLDownloadToFileW
		$a_81_3 = {4f 70 65 6e 4d 75 74 65 78 41 } //1 OpenMutexA
		$a_81_4 = {43 72 65 61 74 65 54 68 72 65 61 64 } //1 CreateThread
		$a_81_5 = {47 65 74 54 65 6d 70 50 61 74 68 57 } //1 GetTempPathW
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}
rule Trojan_Win64_Zusy_EM_MTB_6{
	meta:
		description = "Trojan:Win64/Zusy.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {45 61 73 79 41 6e 74 69 43 68 65 61 74 2e 73 79 73 } //1 EasyAntiCheat.sys
		$a_81_1 = {45 61 63 45 78 70 6c 6f 69 74 2e 70 64 62 } //1 EacExploit.pdb
		$a_81_2 = {5c 44 65 76 69 63 65 5c 69 6e 6a 64 72 76 } //1 \Device\injdrv
		$a_81_3 = {5c 44 6f 73 44 65 76 69 63 65 73 5c 69 6e 6a 64 72 76 } //1 \DosDevices\injdrv
		$a_81_4 = {5c 44 72 69 76 65 72 5c 69 6e 6a 64 72 76 } //1 \Driver\injdrv
		$a_81_5 = {50 73 4c 6f 61 64 65 64 4d 6f 64 75 6c 65 4c 69 73 74 } //1 PsLoadedModuleList
		$a_81_6 = {5b 2d 5d 20 46 61 69 6c 65 64 20 74 6f 20 67 65 74 20 74 65 6d 70 20 70 61 74 68 } //1 [-] Failed to get temp path
		$a_81_7 = {46 61 69 6c 65 64 20 74 6f 20 6f 70 65 6e 20 66 69 6c 65 20 66 6f 72 20 77 72 69 74 69 6e 67 2e } //1 Failed to open file for writing.
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}