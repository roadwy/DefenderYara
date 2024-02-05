
rule VirTool_BAT_Injector_DS_bit{
	meta:
		description = "VirTool:BAT/Injector.DS!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 02 06 02 8e 69 5d 02 06 02 8e 69 5d 91 03 06 03 8e 69 5d 91 61 02 06 17 58 02 8e 69 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 20 03 00 00 00 16 } //01 00 
		$a_01_1 = {00 06 08 06 8e 69 5d 06 08 06 8e 69 5d 91 07 08 07 8e 69 5d 91 61 06 08 17 58 06 8e 69 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 00 08 17 59 0c } //00 00 
	condition:
		any of ($a_*)
 
}