
rule TrojanDropper_Win32_Injector_D{
	meta:
		description = "TrojanDropper:Win32/Injector.D,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 07 00 00 03 00 "
		
	strings :
		$a_02_0 = {83 f8 01 1b db 43 84 db 74 90 01 01 c7 90 01 01 07 00 01 00 90 00 } //01 00 
		$a_00_1 = {8d 04 19 48 33 d2 f7 f1 f7 e9 } //01 00 
		$a_02_2 = {f6 c4 20 0f 85 90 01 02 00 00 a8 02 0f 84 90 01 02 00 00 90 00 } //01 00 
		$a_00_3 = {8b f0 85 f6 74 0c 8b 04 24 50 55 ff d6 85 c0 0f 94 c3 } //01 00 
		$a_00_4 = {65 73 5c 43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 53 65 72 76 65 74 44 6f 77 6e 2e 65 78 65 } //01 00  es\Common Files\ServetDown.exe
		$a_00_5 = {4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 6d 73 74 73 63 2e 65 78 65 } //01 00  NDOWS\SYSTEM32\mstsc.exe
		$a_02_6 = {3a 38 30 38 30 2f 44 6f 77 90 02 03 2e 65 78 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}