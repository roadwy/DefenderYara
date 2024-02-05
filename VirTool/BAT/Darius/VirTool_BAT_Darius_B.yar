
rule VirTool_BAT_Darius_B{
	meta:
		description = "VirTool:BAT/Darius.B,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {02 12 00 28 4b 00 00 0a 2d 11 } //01 00 
		$a_01_1 = {28 6c 00 00 06 0b 02 17 9a 28 6d 00 00 06 0c } //01 00 
		$a_01_2 = {28 70 00 00 06 13 06 07 08 11 04 11 05 11 06 09 } //00 00 
	condition:
		any of ($a_*)
 
}