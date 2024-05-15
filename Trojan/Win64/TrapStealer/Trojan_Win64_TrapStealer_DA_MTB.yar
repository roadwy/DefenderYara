
rule Trojan_Win64_TrapStealer_DA_MTB{
	meta:
		description = "Trojan:Win64/TrapStealer.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //01 00  Go build ID:
		$a_01_1 = {6b 62 69 6e 61 6e 69 2f 73 63 72 65 65 6e 73 68 6f 74 } //01 00  kbinani/screenshot
		$a_01_2 = {6d 61 69 6e 2e 61 6e 74 69 64 65 62 75 67 67 65 72 } //01 00  main.antidebugger
		$a_01_3 = {6d 61 69 6e 2e 64 65 63 72 79 70 74 41 6c 6c 50 61 73 73 77 6f 72 64 73 } //01 00  main.decryptAllPasswords
		$a_01_4 = {6d 61 69 6e 2e 64 65 63 72 79 70 74 41 6c 6c 43 6f 6f 6b 69 65 73 } //01 00  main.decryptAllCookies
		$a_01_5 = {6d 61 69 6e 2e 73 61 76 65 57 69 6e 64 6f 77 73 57 61 6c 6c 70 61 70 65 72 73 } //01 00  main.saveWindowsWallpapers
		$a_01_6 = {6d 61 69 6e 2e 67 65 74 41 75 74 6f 66 69 6c 6c } //00 00  main.getAutofill
	condition:
		any of ($a_*)
 
}