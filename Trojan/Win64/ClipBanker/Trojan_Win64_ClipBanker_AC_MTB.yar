
rule Trojan_Win64_ClipBanker_AC_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c1 89 05 90 01 04 eb 90 01 01 8b 44 24 90 01 01 99 83 e2 03 03 c2 83 e0 03 2b c2 8b 0d 90 01 04 03 c8 8b c1 89 44 24 90 01 01 8b 44 24 90 01 01 8b 0d 90 01 04 0b c8 8b c1 89 05 90 01 04 33 d2 8b 44 24 90 01 01 b9 03 00 00 00 f7 f1 8b 0d 90 01 04 03 c8 8b c1 89 44 24 90 01 01 0f be 05 90 01 04 85 c0 75 90 00 } //01 00 
		$a_01_1 = {4e 73 75 32 4f 64 69 77 6f 64 4f 73 32 } //00 00  Nsu2OdiwodOs2
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_ClipBanker_AC_MTB_2{
	meta:
		description = "Trojan:Win64/ClipBanker.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //01 00  Go build ID:
		$a_01_1 = {45 48 30 7a 53 56 6e 65 5a 50 53 75 46 52 31 31 42 6c 52 39 59 70 70 51 54 56 44 62 68 35 2b 31 36 41 6d 63 4a 69 34 67 31 7a 34 3d } //01 00  EH0zSVneZPSuFR11BlR9YppQTVDbh5+16AmcJi4g1z4=
		$a_01_2 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //01 00  GetClipboardData
		$a_01_3 = {53 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //01 00  SetClipboardData
		$a_01_4 = {55 37 48 56 65 77 68 46 67 41 55 37 4d 50 53 44 39 45 71 4c 39 36 34 31 55 62 41 76 79 68 55 45 } //00 00  U7HVewhFgAU7MPSD9EqL9641UbAvyhUE
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_ClipBanker_AC_MTB_3{
	meta:
		description = "Trojan:Win64/ClipBanker.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 00 6f 00 70 00 79 00 20 00 65 00 76 00 65 00 6e 00 74 00 20 00 64 00 65 00 74 00 65 00 63 00 74 00 65 00 64 00 20 00 61 00 74 00 20 00 7b 00 30 00 7d 00 20 00 28 00 55 00 54 00 43 00 29 00 21 00 } //01 00  Copy event detected at {0} (UTC)!
		$a_01_1 = {43 00 6c 00 69 00 70 00 62 00 6f 00 61 00 72 00 64 00 20 00 41 00 63 00 74 00 69 00 76 00 65 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 3a 00 } //01 00  Clipboard Active Window:
		$a_01_2 = {43 00 6c 00 69 00 70 00 62 00 6f 00 61 00 72 00 64 00 20 00 43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 3a 00 } //01 00  Clipboard Content:
		$a_01_3 = {57 4d 5f 43 4c 49 50 42 4f 41 52 44 55 50 44 41 54 45 } //01 00  WM_CLIPBOARDUPDATE
		$a_01_4 = {53 68 61 72 70 43 6c 69 70 62 6f 61 72 64 2e 65 78 65 } //01 00  SharpClipboard.exe
		$a_01_5 = {43 6c 69 70 62 6f 61 72 64 4e 6f 74 69 66 69 63 61 74 69 6f 6e } //01 00  ClipboardNotification
		$a_01_6 = {41 64 64 43 6c 69 70 62 6f 61 72 64 46 6f 72 6d 61 74 4c 69 73 74 65 6e 65 72 } //00 00  AddClipboardFormatListener
	condition:
		any of ($a_*)
 
}