
rule Trojan_Win64_IcedID_MR_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 28 48 89 44 24 08 eb 31 48 8b 44 24 20 48 89 04 24 eb e9 88 08 48 8b 04 24 eb a9 48 8b 44 24 08 48 ff c0 eb a8 48 8b 4c 24 08 8a 09 eb e5 48 8b 44 24 20 48 83 c4 18 eb } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win64_IcedID_MR_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 05 00 00 "
		
	strings :
		$a_01_0 = {67 69 61 6e 73 66 75 68 79 64 61 73 6a 6b 69 61 73 75 66 68 62 61 73 6a 6b 64 61 73 75 64 68 61 } //10 giansfuhydasjkiasufhbasjkdasudha
		$a_03_1 = {22 20 0b 02 90 01 02 00 1a 00 00 00 de 01 00 00 00 00 00 00 10 00 00 00 10 00 00 00 00 00 80 01 90 00 } //10
		$a_01_2 = {2e 74 64 61 74 61 } //5 .tdata
		$a_01_3 = {53 65 74 43 6f 6e 73 6f 6c 65 57 69 6e 64 6f 77 49 6e 66 6f } //1 SetConsoleWindowInfo
		$a_01_4 = {53 65 74 43 6f 6e 73 6f 6c 65 44 69 73 70 6c 61 79 4d 6f 64 65 } //1 SetConsoleDisplayMode
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*10+(#a_01_2  & 1)*5+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=27
 
}
rule Trojan_Win64_IcedID_MR_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 0d 00 00 "
		
	strings :
		$a_01_0 = {75 65 57 4a 32 79 2e 64 6c 6c } //10 ueWJ2y.dll
		$a_01_1 = {52 6b 70 76 77 6b 2e 64 6c 6c } //10 Rkpvwk.dll
		$a_01_2 = {75 4e 4f 39 61 68 2e 64 6c 6c } //10 uNO9ah.dll
		$a_01_3 = {50 6c 75 67 69 6e 49 6e 69 74 } //5 PluginInit
		$a_01_4 = {44 65 6c 65 74 65 45 6e 68 4d 65 74 61 46 69 6c 65 } //1 DeleteEnhMetaFile
		$a_01_5 = {43 72 65 61 74 65 43 6c 61 73 73 4d 6f 6e 69 6b 65 72 } //1 CreateClassMoniker
		$a_01_6 = {47 65 74 48 47 6c 6f 62 61 6c 46 72 6f 6d 49 4c 6f 63 6b 42 79 74 65 73 } //1 GetHGlobalFromILockBytes
		$a_01_7 = {49 45 55 57 69 33 7a 46 38 54 } //1 IEUWi3zF8T
		$a_01_8 = {53 46 33 4e 54 45 68 70 36 4c 68 } //1 SF3NTEhp6Lh
		$a_01_9 = {58 32 4d 30 66 78 5a 41 42 78 4e } //1 X2M0fxZABxN
		$a_01_10 = {49 6d 6d 47 65 74 49 4d 45 46 69 6c 65 4e 61 6d 65 57 } //1 ImmGetIMEFileNameW
		$a_01_11 = {49 6d 6d 52 65 67 69 73 74 65 72 57 6f 72 64 57 } //1 ImmRegisterWordW
		$a_01_12 = {53 63 72 69 70 74 53 74 72 69 6e 67 46 72 65 65 } //1 ScriptStringFree
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*5+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=18
 
}