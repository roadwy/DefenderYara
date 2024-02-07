
rule Trojan_MacOS_JokerSpy_K_MTB{
	meta:
		description = "Trojan:MacOS/JokerSpy.K!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {58 50 72 6f 74 65 63 74 43 68 65 63 6b } //01 00  XProtectCheck
		$a_00_1 = {43 47 53 53 65 73 73 69 6f 6e 53 63 72 65 65 6e 49 73 4c 6f 63 6b 65 64 } //01 00  CGSSessionScreenIsLocked
		$a_00_2 = {6b 4d 44 49 74 65 6d 44 69 73 70 6c 61 79 4e 61 6d 65 20 3d 20 2a 54 43 43 2e 64 62 } //01 00  kMDItemDisplayName = *TCC.db
		$a_00_3 = {46 75 6c 6c 44 69 73 6b 41 63 63 65 73 73 3a 20 59 45 53 } //01 00  FullDiskAccess: YES
		$a_00_4 = {41 63 63 65 73 73 69 62 69 6c 69 74 79 3a 20 59 45 53 } //01 00  Accessibility: YES
		$a_00_5 = {53 63 72 65 65 6e 52 65 63 6f 72 64 69 6e 67 3a 20 59 45 53 } //01 00  ScreenRecording: YES
		$a_00_6 = {54 68 65 20 73 63 72 65 65 6e 20 69 73 20 63 75 72 72 65 6e 74 6c 79 20 4c 4f 43 4b 45 44 21 } //00 00  The screen is currently LOCKED!
	condition:
		any of ($a_*)
 
}