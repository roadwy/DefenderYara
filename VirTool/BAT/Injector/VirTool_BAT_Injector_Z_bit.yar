
rule VirTool_BAT_Injector_Z_bit{
	meta:
		description = "VirTool:BAT/Injector.Z!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8e 69 5d 58 47 61 d2 52 ?? 17 58 90 09 10 00 d3 ?? 58 ?? d3 ?? 58 47 ?? d3 ?? 7e ?? 00 00 04 } //1
		$a_03_1 = {6f 3a 00 00 0a 5d 58 47 61 d2 52 ?? 17 58 90 09 10 00 d3 ?? 58 ?? d3 ?? 58 47 ?? d3 ?? 7e ?? 00 00 04 } //1
		$a_00_2 = {53 00 54 79 70 65 00 47 54 00 4b } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*2) >=3
 
}