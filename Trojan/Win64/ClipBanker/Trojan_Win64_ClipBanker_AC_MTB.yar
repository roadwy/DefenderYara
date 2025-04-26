
rule Trojan_Win64_ClipBanker_AC_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c1 89 05 ?? ?? ?? ?? eb ?? 8b 44 24 ?? 99 83 e2 03 03 c2 83 e0 03 2b c2 8b 0d ?? ?? ?? ?? 03 c8 8b c1 89 44 24 ?? 8b 44 24 ?? 8b 0d ?? ?? ?? ?? 0b c8 8b c1 89 05 ?? ?? ?? ?? 33 d2 8b 44 24 ?? b9 03 00 00 00 f7 f1 8b 0d ?? ?? ?? ?? 03 c8 8b c1 89 44 24 ?? 0f be 05 ?? ?? ?? ?? 85 c0 75 } //1
		$a_01_1 = {4e 73 75 32 4f 64 69 77 6f 64 4f 73 32 } //1 Nsu2OdiwodOs2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win64_ClipBanker_AC_MTB_2{
	meta:
		description = "Trojan:Win64/ClipBanker.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //1 Go build ID:
		$a_01_1 = {45 48 30 7a 53 56 6e 65 5a 50 53 75 46 52 31 31 42 6c 52 39 59 70 70 51 54 56 44 62 68 35 2b 31 36 41 6d 63 4a 69 34 67 31 7a 34 3d } //1 EH0zSVneZPSuFR11BlR9YppQTVDbh5+16AmcJi4g1z4=
		$a_01_2 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //1 GetClipboardData
		$a_01_3 = {53 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //1 SetClipboardData
		$a_01_4 = {55 37 48 56 65 77 68 46 67 41 55 37 4d 50 53 44 39 45 71 4c 39 36 34 31 55 62 41 76 79 68 55 45 } //1 U7HVewhFgAU7MPSD9EqL9641UbAvyhUE
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win64_ClipBanker_AC_MTB_3{
	meta:
		description = "Trojan:Win64/ClipBanker.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {43 00 6f 00 70 00 79 00 20 00 65 00 76 00 65 00 6e 00 74 00 20 00 64 00 65 00 74 00 65 00 63 00 74 00 65 00 64 00 20 00 61 00 74 00 20 00 7b 00 30 00 7d 00 20 00 28 00 55 00 54 00 43 00 29 00 21 00 } //1 Copy event detected at {0} (UTC)!
		$a_01_1 = {43 00 6c 00 69 00 70 00 62 00 6f 00 61 00 72 00 64 00 20 00 41 00 63 00 74 00 69 00 76 00 65 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 3a 00 } //1 Clipboard Active Window:
		$a_01_2 = {43 00 6c 00 69 00 70 00 62 00 6f 00 61 00 72 00 64 00 20 00 43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 3a 00 } //1 Clipboard Content:
		$a_01_3 = {57 4d 5f 43 4c 49 50 42 4f 41 52 44 55 50 44 41 54 45 } //1 WM_CLIPBOARDUPDATE
		$a_01_4 = {53 68 61 72 70 43 6c 69 70 62 6f 61 72 64 2e 65 78 65 } //1 SharpClipboard.exe
		$a_01_5 = {43 6c 69 70 62 6f 61 72 64 4e 6f 74 69 66 69 63 61 74 69 6f 6e } //1 ClipboardNotification
		$a_01_6 = {41 64 64 43 6c 69 70 62 6f 61 72 64 46 6f 72 6d 61 74 4c 69 73 74 65 6e 65 72 } //1 AddClipboardFormatListener
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}