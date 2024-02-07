
rule VirTool_BAT_Injector_TF_bit{
	meta:
		description = "VirTool:BAT/Injector.TF!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 49 6e 6a 48 6f 73 74 00 } //01 00 
		$a_01_1 = {00 44 6f 63 74 6f 72 00 } //01 00  䐀捯潴r
		$a_01_2 = {00 53 74 72 52 65 76 65 72 73 65 00 } //01 00  匀牴敒敶獲e
		$a_01_3 = {4e 74 52 65 73 75 6d 65 54 68 72 65 61 64 00 4e 74 53 65 74 43 6f 6e 74 65 78 74 54 68 72 65 61 64 00 56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 00 4e 74 57 72 69 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 } //00 00 
	condition:
		any of ($a_*)
 
}