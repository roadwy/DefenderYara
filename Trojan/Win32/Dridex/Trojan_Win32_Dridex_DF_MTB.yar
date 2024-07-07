
rule Trojan_Win32_Dridex_DF_MTB{
	meta:
		description = "Trojan:Win32/Dridex.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {46 33 64 59 50 69 6e 65 } //F3dYPine  3
		$a_80_1 = {65 77 76 74 77 33 34 } //ewvtw34  3
		$a_80_2 = {46 69 6e 64 46 69 72 73 74 55 72 6c 43 61 63 68 65 45 6e 74 72 79 45 78 41 } //FindFirstUrlCacheEntryExA  3
		$a_80_3 = {44 65 6c 65 74 65 50 72 69 6e 74 65 72 44 72 69 76 65 72 45 78 57 } //DeletePrinterDriverExW  3
		$a_80_4 = {49 6e 69 74 69 61 74 65 53 79 73 74 65 6d 53 68 75 74 64 6f 77 6e 45 78 57 } //InitiateSystemShutdownExW  3
		$a_80_5 = {47 65 74 4e 75 6d 62 65 72 4f 66 45 76 65 6e 74 4c 6f 67 52 65 63 6f 72 64 73 } //GetNumberOfEventLogRecords  3
		$a_80_6 = {47 65 74 43 6c 69 70 62 6f 61 72 64 46 6f 72 6d 61 74 4e 61 6d 65 57 } //GetClipboardFormatNameW  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}
rule Trojan_Win32_Dridex_DF_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.DF!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {ba 03 00 00 00 0f c2 c8 02 83 c2 04 83 c2 04 } //10
		$a_01_1 = {29 d7 19 c6 89 74 24 14 89 7c 24 10 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}