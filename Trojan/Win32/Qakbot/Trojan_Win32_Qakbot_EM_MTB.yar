
rule Trojan_Win32_Qakbot_EM_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f4 0f b6 4c 05 } //1
		$a_01_1 = {f7 f6 0f b6 44 15 } //1
		$a_01_2 = {33 c8 8b 45 } //1
		$a_01_3 = {88 4c 05 a4 e9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_Win32_Qakbot_EM_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b cb 83 c6 04 0b cf 0b 4c 24 30 0b d1 8b cd 89 90 a8 00 00 00 2b 48 0c 69 c9 4c 03 00 00 3b f1 72 de } //6
	condition:
		((#a_01_0  & 1)*6) >=6
 
}
rule Trojan_Win32_Qakbot_EM_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 d8 6a 00 e8 90 01 04 2b d8 a1 90 01 04 33 18 89 1d 90 01 04 a1 90 01 04 8b 15 90 01 04 89 10 90 00 } //6
	condition:
		((#a_03_0  & 1)*6) >=6
 
}
rule Trojan_Win32_Qakbot_EM_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 08 89 4d fc 8b 45 fc 89 45 f8 6b 45 08 18 8b 4d f8 03 01 8b e5 5d } //5
		$a_01_1 = {64 65 73 6b 74 6f 70 2e 64 } //1 desktop.d
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_Win32_Qakbot_EM_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //10 DllRegisterServer
		$a_01_1 = {6a 50 55 4d 4f 4f 55 69 45 2e 64 6c 6c } //1 jPUMOOUiE.dll
		$a_01_2 = {41 6d 58 58 36 69 31 57 78 68 } //1 AmXX6i1Wxh
		$a_01_3 = {44 33 67 34 67 43 68 32 } //1 D3g4gCh2
		$a_01_4 = {4a 6b 44 70 7a 44 4f 52 56 55 } //1 JkDpzDORVU
		$a_01_5 = {43 53 4e 5a 34 7a } //1 CSNZ4z
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}
rule Trojan_Win32_Qakbot_EM_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_81_0 = {5a 48 78 62 45 54 6f 70 75 4f 49 } //3 ZHxbETopuOI
		$a_81_1 = {67 55 6d 61 6d 58 50 } //3 gUmamXP
		$a_81_2 = {6a 4b 75 45 6b 68 62 4d 6b 4d 68 59 4b 47 } //3 jKuEkhbMkMhYKG
		$a_81_3 = {53 63 72 69 70 74 43 50 74 6f 58 } //3 ScriptCPtoX
		$a_81_4 = {53 63 72 69 70 74 41 70 70 6c 79 4c 6f 67 69 63 61 6c 57 69 64 74 68 } //3 ScriptApplyLogicalWidth
		$a_81_5 = {43 6c 6f 73 65 45 6e 68 4d 65 74 61 46 69 6c 65 } //3 CloseEnhMetaFile
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3) >=18
 
}