
rule VirTool_BAT_Injector_SM_bit{
	meta:
		description = "VirTool:BAT/Injector.SM!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {51 00 54 00 4e 00 62 00 68 00 4c 00 5e 00 5b 00 5b 00 4e 00 57 00 5d 00 68 00 5e 00 } //01 00  QTNbhL^[[NW]h^
		$a_01_1 = {6b 00 72 00 6e 00 4d 00 75 00 75 00 37 00 6d 00 75 00 75 00 } //01 00  krnMuu7muu
		$a_01_2 = {56 00 6a 00 72 00 77 00 } //00 00  Vjrw
	condition:
		any of ($a_*)
 
}