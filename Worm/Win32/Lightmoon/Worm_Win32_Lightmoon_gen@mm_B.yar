
rule Worm_Win32_Lightmoon_gen@mm_B{
	meta:
		description = "Worm:Win32/Lightmoon.gen@mm!B,SIGNATURE_TYPE_PEHSTR_EXT,38 00 37 00 06 00 00 14 00 "
		
	strings :
		$a_01_0 = {4e 65 77 4d 6f 6f 6e 6c 69 67 68 74 } //14 00  NewMoonlight
		$a_80_1 = {2a 5c 41 44 3a 5c 44 61 74 61 48 65 6c 6c 53 70 61 77 6e 5c 57 41 52 49 4e 47 5f 56 49 52 49 49 5f 4c 41 42 4f 52 41 54 4f 52 59 5c 56 69 72 75 73 20 4b 75 5c 4d 6f 6f 6e 6c 69 67 68 74 20 55 70 64 61 74 65 20 42 61 72 75 5c 50 72 6f 6a 65 63 74 31 2e 76 62 70 } //*\AD:\DataHellSpawn\WARING_VIRII_LABORATORY\Virus Ku\Moonlight Update Baru\Project1.vbp  05 00 
		$a_01_2 = {54 6d 72 54 75 6e 67 67 75 63 6f 6e 65 63 74 } //05 00  TmrTungguconect
		$a_01_3 = {54 6d 72 4b 65 79 4c 6f 67 } //05 00  TmrKeyLog
		$a_01_4 = {54 6d 72 44 6f 73 } //01 00  TmrDos
		$a_01_5 = {53 63 61 6e 45 6d 61 69 6c } //00 00  ScanEmail
	condition:
		any of ($a_*)
 
}