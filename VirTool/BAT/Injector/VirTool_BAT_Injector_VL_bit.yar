
rule VirTool_BAT_Injector_VL_bit{
	meta:
		description = "VirTool:BAT/Injector.VL!bit,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 00 75 00 6e 00 50 00 45 00 44 00 4c 00 4c 00 2e 00 64 00 6c 00 6c 00 } //01 00  RunPEDLL.dll
		$a_01_1 = {52 00 45 00 47 00 47 00 49 00 45 00 } //01 00  REGGIE
		$a_01_2 = {46 00 41 00 55 00 4c 00 54 00 59 00 } //01 00  FAULTY
		$a_01_3 = {53 00 56 00 43 00 48 00 45 00 48 00 45 00 } //00 00  SVCHEHE
	condition:
		any of ($a_*)
 
}