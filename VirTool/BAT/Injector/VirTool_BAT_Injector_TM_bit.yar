
rule VirTool_BAT_Injector_TM_bit{
	meta:
		description = "VirTool:BAT/Injector.TM!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 16 0b 2b 22 06 02 07 6f 90 01 01 00 00 0a 03 07 03 6f 90 01 01 00 00 0a 5d 6f 90 01 01 00 00 0a 61 d1 6f 90 01 01 00 00 0a 26 07 17 58 0b 07 02 6f 90 01 01 00 00 0a 32 d5 06 6f 90 01 01 00 00 0a 2a 90 00 } //01 00 
		$a_01_1 = {00 49 43 6c 69 65 6e 74 00 44 6f 77 6e 6c 6f 61 64 44 4c 4c 00 } //01 00 
		$a_01_2 = {00 47 65 74 44 6f 77 6e 6c 6f 61 64 44 4c 4c 00 } //00 00  䜀瑥潄湷潬摡䱄L
	condition:
		any of ($a_*)
 
}