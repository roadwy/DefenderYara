
rule VirTool_BAT_Injector_gen_S{
	meta:
		description = "VirTool:BAT/Injector.gen!S,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {24 39 61 39 37 31 66 61 33 2d 32 38 38 38 2d 34 32 30 62 2d 61 34 36 30 2d 37 39 34 65 30 37 33 36 37 30 36 61 } //02 00  $9a971fa3-2888-420b-a460-794e0736706a
		$a_01_1 = {43 61 6c 6c 42 79 4e 61 6d 65 } //01 00  CallByName
		$a_01_2 = {62 72 69 63 6f 2e 65 78 65 } //01 00  brico.exe
		$a_01_3 = {74 6f 63 61 74 2e 65 78 65 } //01 00  tocat.exe
		$a_01_4 = {63 6c 6f 6c 6f 69 72 2e 65 78 65 } //00 00  cloloir.exe
		$a_00_5 = {87 10 00 } //00 b6 
	condition:
		any of ($a_*)
 
}