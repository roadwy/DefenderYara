
rule Trojan_Win32_Lazy_MA_MTB{
	meta:
		description = "Trojan:Win32/Lazy.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_01_0 = {b9 04 01 00 00 66 5b 66 83 fb 00 74 0a 66 81 eb f7 00 88 1f 47 e2 ee 66 59 52 c3 } //1
		$a_01_1 = {54 79 59 69 } //5 TyYi
		$a_01_2 = {64 6c 76 72 2e 64 6c 6c } //2 dlvr.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*5+(#a_01_2  & 1)*2) >=8
 
}
rule Trojan_Win32_Lazy_MA_MTB_2{
	meta:
		description = "Trojan:Win32/Lazy.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_80_0 = {6c 69 62 65 6d 62 2e 64 6c 6c } //libemb.dll  1
		$a_00_1 = {77 77 6c 69 62 2e 64 6c 6c } //1 wwlib.dll
		$a_00_2 = {7a 6c 69 62 77 61 70 69 2e 64 6c 6c } //1 zlibwapi.dll
		$a_00_3 = {46 72 65 65 4c 69 62 72 61 72 79 4d 65 6d 6f 72 79 41 6e 64 45 78 69 74 54 68 72 65 61 64 } //5 FreeLibraryMemoryAndExitThread
	condition:
		((#a_80_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*5) >=6
 
}