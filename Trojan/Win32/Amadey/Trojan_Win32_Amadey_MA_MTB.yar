
rule Trojan_Win32_Amadey_MA_MTB{
	meta:
		description = "Trojan:Win32/Amadey.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 4c 49 50 50 45 52 44 4c 4c 2e 64 6c 6c } //5 CLIPPERDLL.dll
		$a_01_1 = {34 43 43 6c 69 70 70 65 72 44 4c 4c 40 40 51 41 45 41 41 56 30 40 41 42 56 30 40 40 5a } //2 4CClipperDLL@@QAEAAV0@ABV0@@Z
		$a_01_2 = {3f 3f 34 43 43 6c 69 70 70 65 72 44 4c 4c 40 40 51 41 45 41 41 56 30 40 24 24 51 41 56 30 40 40 5a } //2 ??4CClipperDLL@@QAEAAV0@$$QAV0@@Z
		$a_01_3 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //1 GetClipboardData
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=10
 
}
rule Trojan_Win32_Amadey_MA_MTB_2{
	meta:
		description = "Trojan:Win32/Amadey.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 3a 5c 4d 6b 74 6d 70 5c 41 6d 61 64 65 79 5c 52 65 6c 65 61 73 65 5c 41 6d 61 64 65 79 2e 70 64 62 } //5 D:\Mktmp\Amadey\Release\Amadey.pdb
		$a_03_1 = {6a 40 68 00 30 00 00 ff 77 50 50 ff b5 ?? ?? ?? ?? ff 15 } //1
		$a_03_2 = {8d 0c 33 03 4e 3c 6a 00 ff b1 ?? ?? ?? ?? 8b 81 ?? ?? ?? ?? 03 c6 50 8b 81 ?? ?? ?? ?? 03 85 ?? fe ff ff 50 ff b5 ?? fe ff ff ff 15 ?? ?? ?? ?? 8b 8d ?? fe ff ff 8d 5b 28 0f b7 47 06 41 89 8d ?? fe ff ff 3b c8 7e b8 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=7
 
}