
rule TrojanSpy_Win32_Banker_AOT{
	meta:
		description = "TrojanSpy:Win32/Banker.AOT,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 61 78 69 6d 75 73 64 65 63 69 6d 75 73 2e 63 70 6c } //1 maximusdecimus.cpl
		$a_01_1 = {73 65 72 61 73 61 2e 63 6f 6d 2e 62 72 } //1 serasa.com.br
		$a_01_2 = {63 6d 64 20 2f 6b 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 6a 61 76 61 5f 75 70 64 61 74 65 33 32 2e 63 6d 64 } //1 cmd /k C:\ProgramData\java_update32.cmd
		$a_01_3 = {30 2e 67 69 66 3f 33 30 37 36 34 35 35 } //1 0.gif?3076455
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanSpy_Win32_Banker_AOT_2{
	meta:
		description = "TrojanSpy:Win32/Banker.AOT,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b d0 80 c2 bf 80 ea 1a 73 0d 3c 4d 75 07 80 fb 48 75 02 b0 4e } //2
		$a_01_1 = {63 6d 64 20 2f 6b 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 6a 61 76 61 5f 75 70 64 61 74 65 33 32 2e 63 6d 64 00 } //2
		$a_01_2 = {50 72 6f 6a 65 63 74 36 36 36 00 } //2
		$a_01_3 = {75 72 6c 3a 20 00 } //1 牵㩬 
		$a_01_4 = {75 72 6c 32 3a 20 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}
rule TrojanSpy_Win32_Banker_AOT_3{
	meta:
		description = "TrojanSpy:Win32/Banker.AOT,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 69 74 65 6e 65 74 2e 73 65 72 61 73 61 2e 63 6f 6d 2e 62 72 } //5 sitenet.serasa.com.br
		$a_01_1 = {63 6d 64 20 2f 6b 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 6a 61 76 61 5f 75 70 64 61 74 65 33 32 2e 63 6d 64 } //5 cmd /k C:\ProgramData\java_update32.cmd
		$a_01_2 = {75 72 6c 32 3a } //1 url2:
		$a_01_3 = {77 69 6e 3a } //1 win:
		$a_01_4 = {49 45 78 70 6c 6f 72 65 5f 45 78 70 6c 6f 72 65 72 5f 53 65 72 76 65 72 } //1 IExplore_Explorer_Server
		$a_00_5 = {8b 55 f0 33 db 8a 5c 10 ff 33 5d e4 3b f3 7d 04 2b de eb 0c 3b f3 7c 08 81 c3 ff 00 00 00 2b de 8d 45 d4 8b d3 e8 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1) >=14
 
}
rule TrojanSpy_Win32_Banker_AOT_4{
	meta:
		description = "TrojanSpy:Win32/Banker.AOT,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_03_0 = {20 75 72 6c 3a 20 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-10] 20 75 72 6c 32 3a 20 00 } //1
		$a_03_1 = {66 ba 57 00 a1 ?? ?? ?? ?? e8 08 fc ff ff 68 4d 01 00 00 e8 ?? ?? ?? ?? 6a 00 8d 55 f4 b8 ?? ?? ?? ?? e8 a7 f7 ff ff ff 75 f4 68 ?? ?? ?? ?? ff 75 fc 8d 45 f8 ba 03 00 00 00 e8 ?? ?? ?? ?? 8b 45 f8 e8 ?? ?? ?? ?? 50 e8 } //1
		$a_03_2 = {75 17 8d 55 d4 8b c3 e8 e4 f1 ff ff 8b 55 d4 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 33 c9 b2 01 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 45 f4 8b 45 f4 c7 80 9c 00 00 00 e8 03 00 00 8d 55 d0 b8 ?? ?? ?? ?? e8 06 ca ff ff 8b 55 d0 8d 45 f0 8b 4d f8 e8 ?? ?? ?? ?? 8d 55 cc b8 ?? ?? ?? ?? e8 eb c9 ff ff } //1
		$a_01_3 = {8b 45 08 c7 40 fc c8 00 00 00 8b 45 08 ff 40 fc 8d 45 e8 50 8b 45 fc 50 8b 00 ff 50 20 85 c0 0f 85 37 01 00 00 83 7d e8 00 0f 8e 2d 01 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=1
 
}