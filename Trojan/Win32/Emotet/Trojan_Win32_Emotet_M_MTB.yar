
rule Trojan_Win32_Emotet_M_MTB{
	meta:
		description = "Trojan:Win32/Emotet.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 "
		
	strings :
		$a_00_0 = {f7 e9 03 d1 8b 8c fe 14 07 00 00 c1 fa 0e 8b c2 c1 e8 1f 03 c2 4b 8b ac c6 14 07 00 00 8b 94 fe 18 07 00 00 89 ac fe 14 07 } //10
		$a_81_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //3 DllRegisterServer
		$a_81_2 = {68 61 31 6d 65 35 69 } //3 ha1me5i
		$a_81_3 = {74 62 62 49 37 72 32 37 64 63 6c 32 4d } //3 tbbI7r27dcl2M
	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3) >=19
 
}
rule Trojan_Win32_Emotet_M_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 0c 00 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 ff d7 6a 00 6a 00 ff d7 6a 00 6a 00 ff d7 8b 4c 24 14 b8 ?? ?? ?? ?? f7 e6 c1 ea 05 6b d2 2e 8b c6 2b c2 8a 14 41 30 14 1e 83 c6 01 3b f5 75 cc } //5
		$a_02_1 = {6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 55 08 03 55 f0 0f b6 02 8b 4d fc 03 4d ec 0f b6 d1 0f b6 8c 15 ?? ?? ff ff 33 c1 8b 55 08 03 55 f0 88 02 e9 ?? ff ff ff 8b 4d e4 33 cd e8 ?? ?? ?? ?? 8b e5 5d c3 } //5
		$a_02_2 = {6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 55 08 03 55 ec 33 c0 8a 02 8b 4d fc 03 4d f8 81 e1 ff 00 00 00 33 d2 8a 94 0d ?? ?? ff ff 33 c2 8b 4d 08 03 4d ec 88 01 e9 ?? ?? ff ff 8b e5 5d c3 } //5
		$a_02_3 = {6a 00 6a 00 ff d6 6a 00 6a 00 ff d6 6a 00 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 02 5c 24 14 8b 44 24 18 0f b6 d3 8a 4c 14 1c 30 0c 38 47 3b bc 24 ?? ?? 00 00 0f 8c ?? ff ff ff } //5
		$a_00_4 = {45 33 c9 81 e5 fe 01 00 00 33 c0 8a 4c 2c 10 03 d9 81 e3 fe 01 00 00 8a 44 1c 10 88 44 2c 10 02 c1 25 ff 00 00 00 88 4c 1c 10 8a 0c 32 8a 44 04 10 32 c8 88 0c 32 42 3b d7 7c c5 } //5
		$a_02_5 = {ff d6 57 57 ff d6 02 5d f8 8b 4d fc 8b 45 08 0f b6 d3 8a 94 15 c4 fe ff ff 03 c1 30 10 41 3b 4d 0c 89 4d fc 0f 8c ?? ff ff ff } //5
		$a_02_6 = {8b 54 24 1c 52 56 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 18 ff d6 39 7c 24 4c 72 0d 8b 44 24 38 50 e8 ?? ?? ?? ?? 83 c4 04 8b 4c 24 54 64 89 0d 00 00 00 00 59 5f 5e 5b } //1
		$a_02_7 = {8b 55 f8 52 8b 45 ec 50 8b 4d e0 51 e8 ?? ?? ?? ?? 83 c4 10 8b 55 e0 89 55 fc ff 55 fc 89 45 e8 6a 00 ff 15 ?? ?? ?? ?? 8b e5 5d c3 } //1
		$a_02_8 = {8b 45 f0 50 8b 4d fc 51 8b 55 d8 52 e8 ?? ?? ?? ?? 83 c4 10 8b 45 d8 89 45 e8 ff 55 e8 89 45 ec 6a 00 ff 15 ?? ?? ?? ?? 8b e5 5d c3 } //1
		$a_02_9 = {6a 40 68 00 30 00 00 56 6a 00 53 ff d0 56 8b f8 55 57 e8 ?? ?? ?? ?? 83 c4 0c 6a ?? 68 ?? ?? ?? ?? 56 57 e8 ?? ?? ?? ?? 83 c4 10 ff d7 } //1
		$a_00_10 = {8b 44 24 14 53 6a 40 68 00 30 00 00 50 53 56 ff d7 } //1
		$a_02_11 = {ff 75 fc 53 e8 ?? ?? ff ff 83 c4 10 ff d3 57 ff 15 ?? ?? ?? 00 5f 5e 5b c9 c3 } //1
	condition:
		((#a_02_0  & 1)*5+(#a_02_1  & 1)*5+(#a_02_2  & 1)*5+(#a_02_3  & 1)*5+(#a_00_4  & 1)*5+(#a_02_5  & 1)*5+(#a_02_6  & 1)*1+(#a_02_7  & 1)*1+(#a_02_8  & 1)*1+(#a_02_9  & 1)*1+(#a_00_10  & 1)*1+(#a_02_11  & 1)*1) >=6
 
}