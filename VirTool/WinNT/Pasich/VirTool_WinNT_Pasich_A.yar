
rule VirTool_WinNT_Pasich_A{
	meta:
		description = "VirTool:WinNT/Pasich.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_03_0 = {68 31 30 44 54 6a 30 6a 00 8b f8 ff 15 ?? ?? 40 00 8b f0 85 f6 74 ?? a1 ?? ?? 40 00 6a 01 6a 01 50 6a 00 } //1
		$a_01_1 = {6a 04 68 00 10 00 00 8d 4c 24 08 51 6a 00 8d 54 24 18 52 6a ff c7 44 24 20 00 00 00 00 c7 44 24 18 18 00 00 00 ff 15 } //1
		$a_03_2 = {83 65 fc 00 83 65 e4 00 6a 25 e8 ?? ?? 00 00 8b f0 89 75 dc 85 f6 74 ?? c6 45 d4 e9 33 c0 8d 7d d5 ab 8b 45 08 89 45 e0 ff 75 e0 } //2
		$a_01_3 = {83 eb 05 89 5d d5 0f 20 c0 8b c8 81 e1 ff ff fe ff 0f 22 c1 8d 75 d4 a5 a4 0f 22 c0 83 4d fc ff } //2
		$a_01_4 = {8d 78 fb a5 a4 0f 22 c1 c6 45 f0 eb c6 45 f1 f9 eb 08 2b d8 } //2
		$a_01_5 = {50 73 53 65 74 4c 6f 61 64 49 6d 61 67 65 4e 6f 74 69 66 79 52 6f 75 74 69 6e 65 } //1 PsSetLoadImageNotifyRoutine
		$a_01_6 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //1 KeServiceDescriptorTable
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}