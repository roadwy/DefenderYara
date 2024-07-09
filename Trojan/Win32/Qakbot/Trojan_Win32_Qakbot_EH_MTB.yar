
rule Trojan_Win32_Qakbot_EH_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 d8 8b 12 03 55 a8 2b d0 8b 45 d8 89 10 6a 00 e8 ?? ?? ?? ?? 8b 55 c4 03 55 a4 2b d0 89 55 a0 } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}
rule Trojan_Win32_Qakbot_EH_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 18 89 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 02 a1 ?? ?? ?? ?? 83 c0 04 a3 ?? ?? ?? ?? 33 c0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}
rule Trojan_Win32_Qakbot_EH_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 12 03 55 a8 2b d0 8b 45 d8 89 10 6a 00 e8 ?? ?? ?? ?? 8b 55 c4 03 55 a4 2b d0 89 55 a0 6a 00 e8 ?? ?? ?? ?? 8b 55 a0 2b d0 8b 45 d8 33 10 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}
rule Trojan_Win32_Qakbot_EH_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 97 fc 00 00 00 8b 87 44 01 00 00 8b 8f 3c 01 00 00 8b 04 82 31 04 8a } //3
		$a_01_1 = {8b 8f 44 01 00 00 8b 87 fc 00 00 00 8b b7 3c 01 00 00 8b 97 f8 00 00 00 8b 04 88 01 04 b2 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}
rule Trojan_Win32_Qakbot_EH_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d8 4b 6a 00 e8 ?? ?? ?? ?? 2b d8 4b a1 ?? ?? ?? ?? 33 18 89 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 02 a1 ?? ?? ?? ?? 83 c0 04 a3 ?? ?? ?? ?? 33 c0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}
rule Trojan_Win32_Qakbot_EH_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 02 33 c0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 0f 82 90 09 18 00 8b 15 ?? ?? ?? ?? 33 02 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_EH_MTB_7{
	meta:
		description = "Trojan:Win32/Qakbot.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4b 55 65 69 4f 51 6c 64 79 73 61 } //1 KUeiOQldysa
		$a_01_1 = {63 69 78 64 53 45 4a 68 6a 4a } //1 cixdSEJhjJ
		$a_01_2 = {5a 78 47 73 53 6d 41 49 65 64 4f 53 } //1 ZxGsSmAIedOS
		$a_01_3 = {4e 57 4a 4c 6a 52 46 41 58 62 77 74 75 64 71 } //1 NWJLjRFAXbwtudq
		$a_01_4 = {47 74 66 62 73 44 7a 41 46 69 4a 68 77 49 57 6e 6f 6c } //1 GtfbsDzAFiJhwIWnol
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Qakbot_EH_MTB_8{
	meta:
		description = "Trojan:Win32/Qakbot.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {55 42 4b 67 6b 52 61 68 57 7a 59 } //1 UBKgkRahWzY
		$a_01_1 = {52 61 6c 6c 6f 63 61 74 65 50 6f 73 69 74 69 6f 6e 73 } //1 RallocatePositions
		$a_01_2 = {52 61 70 70 6c 79 49 6e 73 65 72 74 69 6f 6e 73 } //1 RapplyInsertions
		$a_01_3 = {4c 45 47 6c 79 70 68 53 74 6f 72 61 67 65 } //1 LEGlyphStorage
		$a_01_4 = {76 62 65 6e 67 } //1 vbeng
		$a_01_5 = {7a 63 63 6d 70 } //1 zccmp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Trojan_Win32_Qakbot_EH_MTB_9{
	meta:
		description = "Trojan:Win32/Qakbot.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {77 6e 74 6d 73 63 69 31 32 2e 70 72 6f 5c 62 69 6e 5c 66 6f 72 75 69 2e 70 64 62 } //1 wntmsci12.pro\bin\forui.pdb
		$a_01_1 = {63 6f 6d 2e 73 75 6e 2e 73 74 61 72 2e 73 68 65 65 74 2e 46 6f 72 6d 75 6c 61 4f 70 43 6f 64 65 4d 61 70 45 6e 74 72 79 } //1 com.sun.star.sheet.FormulaOpCodeMapEntry
		$a_01_2 = {66 6f 72 2e 64 6c 6c } //1 for.dll
		$a_01_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_01_4 = {46 4f 52 4d 55 4c 41 5f 48 49 44 5f 46 4f 52 4d 55 4c 41 5f 46 41 50 } //1 FORMULA_HID_FORMULA_FAP
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}