
rule PWS_Win32_Wowsteal_ZF{
	meta:
		description = "PWS:Win32/Wowsteal.ZF,SIGNATURE_TYPE_PEHSTR,33 00 33 00 08 00 00 0a 00 "
		
	strings :
		$a_01_0 = {5c 00 4e 00 65 00 77 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 2e 00 76 00 62 00 70 00 } //0a 00  \NewProject.vbp
		$a_01_1 = {4d 6f 6f 6e 48 6f 6f 6b } //0a 00  MoonHook
		$a_01_2 = {77 65 62 55 70 64 61 74 65 } //0a 00  webUpdate
		$a_01_3 = {46 75 63 6b 53 68 61 6e 64 61 } //0a 00  FuckShanda
		$a_01_4 = {69 66 79 6f 75 64 6f 74 68 61 74 61 67 61 69 6e 69 77 69 6c 6c 6b 69 63 6b 79 6f 75 72 61 73 73 } //01 00  ifyoudothatagainiwillkickyourass
		$a_01_5 = {74 69 6d 4d 6f 6e 48 6f 6f 6b } //01 00  timMonHook
		$a_01_6 = {74 69 6d 4d 6f 6e 57 69 6e 64 6f 77 } //01 00  timMonWindow
		$a_01_7 = {53 45 5f 44 45 42 55 47 5f 4e 41 4d 45 } //00 00  SE_DEBUG_NAME
	condition:
		any of ($a_*)
 
}