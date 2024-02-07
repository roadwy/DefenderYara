
rule VirTool_BAT_Injector_JB_bit{
	meta:
		description = "VirTool:BAT/Injector.JB!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_00_0 = {2b 11 07 08 07 08 91 02 08 1f 10 5d 91 61 9c 08 17 d6 0c 08 09 31 eb 07 0a 2b 00 06 2a } //01 00 
		$a_01_1 = {00 73 75 63 6b 69 74 00 } //00 00  猀捵楫t
	condition:
		any of ($a_*)
 
}