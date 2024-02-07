
rule VirTool_Win32_Vbinder_AU{
	meta:
		description = "VirTool:Win32/Vbinder.AU,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {49 00 6e 00 64 00 65 00 74 00 65 00 63 00 74 00 61 00 62 00 6c 00 65 00 73 00 2e 00 76 00 62 00 70 00 00 00 } //01 00 
		$a_01_1 = {45 6e 63 72 79 70 74 46 69 6c 65 00 44 65 63 72 79 70 74 46 69 6c 65 00 } //01 00  湅牣灹䙴汩e敄牣灹䙴汩e
		$a_01_2 = {52 74 6c 4d 6f 76 65 4d 65 6d 6f 72 79 00 } //00 00  瑒䵬癯䵥浥牯y
	condition:
		any of ($a_*)
 
}