
rule PWS_Win32_Cimuz_gen_dll{
	meta:
		description = "PWS:Win32/Cimuz.gen.dll!A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 03 00 00 05 00 "
		
	strings :
		$a_00_0 = {68 6f 6f 6b 2e 64 6c 6c 00 53 65 74 48 6f 6f 6b 00 55 6e 53 65 74 48 6f 6f 6b } //01 00  潨歯搮汬匀瑥潈歯唀卮瑥潈歯
		$a_01_1 = {6a 01 58 39 44 24 08 75 0a 8b 4c 24 04 89 } //01 00 
		$a_01_2 = {81 7e 04 02 01 00 00 75 } //00 00 
	condition:
		any of ($a_*)
 
}