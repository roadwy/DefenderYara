
rule VirTool_BAT_Injector_MD_bit{
	meta:
		description = "VirTool:BAT/Injector.MD!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {02 06 02 06 91 03 07 91 61 d2 9c 07 17 58 0b 07 03 8e 69 32 eb 06 17 58 0a } //01 00 
		$a_03_1 = {45 00 6e 00 74 00 72 00 79 00 50 00 6f 00 69 00 6e 00 74 00 90 01 02 47 00 65 00 74 00 45 00 78 00 65 00 63 00 75 00 74 00 69 00 6e 00 67 00 41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 90 01 02 4c 00 6f 00 61 00 64 00 90 00 } //01 00 
		$a_01_2 = {53 79 73 74 65 6d 2e 52 65 66 6c 65 63 74 69 6f 6e 00 4d 65 74 68 6f 64 49 6e 66 6f } //00 00 
	condition:
		any of ($a_*)
 
}