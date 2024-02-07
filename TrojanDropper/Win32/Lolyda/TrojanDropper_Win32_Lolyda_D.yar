
rule TrojanDropper_Win32_Lolyda_D{
	meta:
		description = "TrojanDropper:Win32/Lolyda.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {46 4f 4e 74 53 5c 43 6f 6d 52 65 73 2e 64 6c 6c } //01 00  FONtS\ComRes.dll
		$a_00_1 = {46 6f 6e 74 53 5c 67 74 68 25 30 32 78 2a 2e 74 74 66 } //01 00  FontS\gth%02x*.ttf
		$a_02_2 = {2d 20 05 00 00 8d 8d 90 01 04 50 68 20 05 00 00 8d 95 90 01 04 51 52 e8 90 02 0f 90 90 90 02 0f 8d 85 90 01 04 68 20 05 00 00 8d 8d 90 01 04 50 51 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}