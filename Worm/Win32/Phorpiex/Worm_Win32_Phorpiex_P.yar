
rule Worm_Win32_Phorpiex_P{
	meta:
		description = "Worm:Win32/Phorpiex.P,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {99 b9 0a 00 00 00 f7 f9 52 56 68 ?? ?? ?? ?? 56 (ff d3|e8 ?? ?? ??) ?? 83 c4 10 83 ef 01 75 ?? 5f c6 46 } //1
		$a_03_1 = {80 38 00 74 ?? 50 8d 44 24 ?? 50 (ff d7|e8 ?? ?? ??) ?? 83 c4 08 85 c0 75 ?? 46 83 fe 03 72 } //1
		$a_01_2 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}