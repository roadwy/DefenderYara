
rule TrojanDownloader_Win32_Cutwail_CB{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.CB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 07 00 00 "
		
	strings :
		$a_03_0 = {07 00 01 00 8d 85 ?? ?? ff ff 50 8b 8d ?? ?? ff ff 51 ff 15 90 09 06 00 c7 } //1
		$a_03_1 = {81 e2 00 f0 00 00 c1 fa 0c 66 89 ?? ?? 8b 45 ?? 8b 4d ?? 0f bf 14 41 81 e2 ff 0f 00 00 } //1
		$a_03_2 = {ff ff 50 ff 75 ?? c7 85 ?? ?? ff ff 07 00 01 00 ff 15 90 09 04 00 8d 85 } //1
		$a_03_3 = {8d 54 50 08 66 83 3a 00 74 ?? 0f b7 12 8b fa c1 fa 0c 80 e2 0f 81 e7 ff 0f 00 00 80 } //1
		$a_00_4 = {66 be c5 ee 66 81 ee b6 ee 2b f1 2b fe eb e3 } //10
		$a_01_5 = {5c 73 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 } //10 \system32\svchost.exe
		$a_03_6 = {53 6a 04 5b be 00 02 00 80 39 5d ?? 75 05 be 80 33 80 80 57 57 6a 03 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_00_4  & 1)*10+(#a_01_5  & 1)*10+(#a_03_6  & 1)*1) >=22
 
}