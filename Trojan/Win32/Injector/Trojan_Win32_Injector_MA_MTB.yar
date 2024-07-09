
rule Trojan_Win32_Injector_MA_MTB{
	meta:
		description = "Trojan:Win32/Injector.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4d f8 83 c1 01 89 4d f8 8b 55 f8 3b 55 e8 0f 83 ?? ?? ?? ?? 8b 45 f4 03 45 f8 8a 08 88 4d ff } //2
		$a_01_1 = {4c 6f 61 64 65 72 2e 70 64 62 } //1 Loader.pdb
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_Win32_Injector_MA_MTB_2{
	meta:
		description = "Trojan:Win32/Injector.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {75 6a 6d 61 6b 66 75 6e 2e 64 6c 6c } //1 ujmakfun.dll
		$a_01_1 = {68 72 79 61 62 77 } //1 hryabw
		$a_01_2 = {69 6e 65 68 70 } //1 inehp
		$a_01_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_4 = {43 72 65 61 74 65 46 69 6c 65 } //1 CreateFile
		$a_01_5 = {57 4e 65 74 41 64 64 43 6f 6e 6e 65 63 74 69 6f 6e } //1 WNetAddConnection
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Trojan_Win32_Injector_MA_MTB_3{
	meta:
		description = "Trojan:Win32/Injector.MA!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {c7 44 24 8c 2a 00 00 00 83 ff 03 48 } //3
		$a_01_1 = {83 fe 3f c7 84 24 7c ff ff ff f6 00 00 00 83 f9 40 89 3e } //3
		$a_01_2 = {c7 44 24 8c b3 00 00 00 81 fa aa 00 00 00 81 ff cd 00 00 00 81 f9 d2 00 00 00 } //4
		$a_01_3 = {89 3e c7 84 24 7c ff ff ff 00 00 00 00 83 fa 0a 83 f9 3f } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*4+(#a_01_3  & 1)*2) >=6
 
}