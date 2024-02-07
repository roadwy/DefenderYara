
rule VirTool_BAT_Injector_VA_bit{
	meta:
		description = "VirTool:BAT/Injector.VA!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 00 75 00 6e 00 50 00 45 00 2e 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 } //01 00  RunPE.Protect
		$a_01_1 = {6f 08 00 00 0a 0d 06 09 6c 23 00 00 00 00 00 00 18 40 5b 23 00 00 00 00 00 00 18 40 5b 23 00 00 00 00 00 00 1c 40 5b 28 09 00 00 0a b7 28 0a 00 00 0a 28 0b 00 00 0a } //01 00 
		$a_01_2 = {44 65 63 72 79 70 74 00 4c 6f 61 64 69 6e 67 00 4d 61 69 6e } //00 00  敄牣灹t潌摡湩g慍湩
	condition:
		any of ($a_*)
 
}