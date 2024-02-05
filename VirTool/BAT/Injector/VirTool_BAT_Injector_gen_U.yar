
rule VirTool_BAT_Injector_gen_U{
	meta:
		description = "VirTool:BAT/Injector.gen!U,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {28 15 00 00 0a 21 90 01 06 ce 08 73 16 00 00 0a 28 17 00 00 0a 2c 06 73 18 00 00 0a 7a 90 00 } //01 00 
		$a_01_1 = {62 75 74 65 00 ee 80 81 00 ee 80 82 00 ee 80 83 00 56 65 72 } //01 00 
		$a_01_2 = {65 66 36 33 67 38 67 38 2d 38 67 35 33 } //01 00 
	condition:
		any of ($a_*)
 
}