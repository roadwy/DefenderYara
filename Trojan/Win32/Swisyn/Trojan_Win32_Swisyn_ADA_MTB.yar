
rule Trojan_Win32_Swisyn_ADA_MTB{
	meta:
		description = "Trojan:Win32/Swisyn.ADA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 09 00 00 "
		
	strings :
		$a_80_0 = {57 69 6e 2e 75 45 78 57 61 74 63 68 } //Win.uExWatch  3
		$a_80_1 = {6d 45 78 49 6e 74 65 72 6e 65 74 } //mExInternet  3
		$a_80_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //URLDownloadToFileA  3
		$a_80_3 = {44 65 6c 65 74 65 55 72 6c 43 61 63 68 65 45 6e 74 72 79 41 } //DeleteUrlCacheEntryA  3
		$a_80_4 = {74 6d 72 53 65 63 } //tmrSec  3
		$a_80_5 = {74 6d 72 50 72 69 } //tmrPri  3
		$a_80_6 = {47 64 69 70 47 65 74 49 6d 61 67 65 45 6e 63 6f 64 65 72 73 } //GdipGetImageEncoders  3
		$a_80_7 = {43 6c 69 65 6e 74 54 6f 53 63 72 65 65 6e } //ClientToScreen  3
		$a_80_8 = {53 68 65 6c 6c 49 45 5f 57 69 6e 64 6f 77 52 65 67 69 73 74 65 72 65 64 } //ShellIE_WindowRegistered  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3+(#a_80_8  & 1)*3) >=27
 
}