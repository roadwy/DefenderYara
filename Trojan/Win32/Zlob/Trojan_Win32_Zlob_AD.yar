
rule Trojan_Win32_Zlob_AD{
	meta:
		description = "Trojan:Win32/Zlob.AD,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_00_0 = {2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 䐮䱌䐀汬慃啮汮慯乤睯䐀汬敇䍴慬獳扏敪瑣䐀汬敒楧瑳牥敓癲牥䐀汬湕敲楧瑳牥敓癲牥
		$a_00_1 = {49 6d 61 67 65 4c 69 73 74 5f 52 65 70 6c 61 63 65 49 63 6f 6e } //1 ImageList_ReplaceIcon
		$a_00_2 = {47 65 74 43 6c 69 65 6e 74 52 65 63 74 } //1 GetClientRect
		$a_00_3 = {52 65 67 53 65 74 56 61 6c 75 65 45 78 } //1 RegSetValueEx
		$a_00_4 = {53 74 72 69 6e 67 46 72 6f 6d 47 55 49 44 32 } //1 StringFromGUID2
		$a_00_5 = {47 65 74 55 73 65 72 4f 62 6a 65 63 74 49 6e 66 6f 72 6d 61 74 69 6f 6e } //1 GetUserObjectInformation
		$a_00_6 = {54 00 4f 00 4f 00 4c 00 42 00 41 00 52 00 } //1 TOOLBAR
		$a_02_7 = {68 06 00 02 00 6a 00 6a 00 6a 00 8b 95 ?? ?? ff ff 52 68 02 00 00 80 ff 15 ?? ?? ?? ?? 6a 00 6a 01 8d 4d ?? e8 ?? ?? ff ff ba ?? ?? ?? ?? 8d 4d ?? e8 ?? ?? ff ff 89 45 ?? 8b 45 ?? 83 78 ?? 08 72 0e 8b 4d ?? 8b 51 04 89 95 ?? ?? ff ff eb ?? 8b 45 ?? 83 c0 04 89 85 ?? ?? ff ff 6a 00 6a 00 6a 03 6a 00 } //1
		$a_02_8 = {6a 28 6a 20 5e 56 e8 ?? ?? ff ff 59 59 3b c7 0f 84 ?? ?? 00 00 a3 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 8d 88 00 05 00 00 eb ?? c6 40 04 00 83 08 ff c6 40 05 0a 89 78 08 c6 40 24 00 c6 40 25 0a c6 40 26 0a 83 c0 28 8b 0d ?? ?? ?? ?? 81 c1 00 05 00 00 } //1
		$a_02_9 = {8b 44 24 04 8b 00 8b 00 3d 4d 4f 43 e0 74 18 3d 63 73 6d e0 75 ?? e8 ?? ?? ff ff 83 a0 90 90 00 00 00 00 e9 ?? ?? 00 00 e8 ?? ?? ff ff 83 b8 90 90 00 00 00 00 7e ?? e8 ?? ?? ff ff 05 90 90 00 00 00 ff 08 33 c0 c3 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_02_7  & 1)*1+(#a_02_8  & 1)*1+(#a_02_9  & 1)*1) >=10
 
}