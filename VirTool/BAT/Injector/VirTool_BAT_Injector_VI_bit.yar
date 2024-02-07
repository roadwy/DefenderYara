
rule VirTool_BAT_Injector_VI_bit{
	meta:
		description = "VirTool:BAT/Injector.VI!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {5a 20 e8 03 00 00 6a 5b 0b 06 90 09 07 00 0a 02 7e 90 01 01 00 00 0a 90 00 } //01 00 
		$a_03_1 = {11 05 11 0a 90 01 02 00 00 1b 11 0c 11 07 58 11 09 59 93 61 11 0b 90 01 02 00 00 1b 11 09 11 0c 58 1f 11 58 11 08 5d 93 61 d1 90 00 } //01 00 
		$a_00_2 = {62 00 69 00 62 00 64 00 61 00 67 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //00 00  bibdag.Properties.Resources
	condition:
		any of ($a_*)
 
}