
rule Backdoor_Win32_Zloader_STC{
	meta:
		description = "Backdoor:Win32/Zloader.STC,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 06 00 00 "
		
	strings :
		$a_03_0 = {55 1e 00 00 [0-07] 55 11 00 00 } //10
		$a_80_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 43 4f 4d 53 70 79 } //Software\Microsoft\COMSpy  10
		$a_80_2 = {00 46 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 } //  10
		$a_03_3 = {6a 00 6a 01 6a 00 6a 00 8d 45 fc 50 ff 15 ?? ?? ?? ?? 85 c0 75 04 33 c0 eb 1c 6a 08 6a 01 6a 00 6a 00 8d 4d fc 51 ff } //1
		$a_03_4 = {41 b9 01 00 00 00 45 33 c0 33 d2 48 8d 4c ?? ?? ff 15 ?? ?? ?? ?? 85 c0 75 [0-06] c7 ?? ?? ?? 08 00 00 00 41 b9 01 00 00 00 45 33 c0 33 d2 48 8d 4c 09 30 01 02 ff 15 } //1
		$a_03_5 = {41 bf 01 00 00 00 48 8d 4d 48 45 33 c0 33 d2 45 8b cf 89 45 38 ff 15 ?? ?? ?? ?? 85 c0 75 43 48 8d 4d 48 45 8b cf 45 33 c0 33 d2 c7 44 24 20 08 00 00 00 ff 15 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*10+(#a_80_2  & 1)*10+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=21
 
}