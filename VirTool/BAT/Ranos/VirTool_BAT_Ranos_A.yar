
rule VirTool_BAT_Ranos_A{
	meta:
		description = "VirTool:BAT/Ranos.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {32 66 64 33 32 38 62 66 2d 33 39 37 62 2d 34 65 39 36 2d 39 38 34 32 2d 38 35 39 33 37 63 64 32 64 32 37 61 } //1 2fd328bf-397b-4e96-9842-85937cd2d27a
		$a_01_1 = {2f 04 b1 03 3f 04 30 01 ac 03 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}