
rule VirTool_WinNT_Nedsym_gen_C{
	meta:
		description = "VirTool:WinNT/Nedsym.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 ff d3 83 c4 0c 85 c0 74 61 83 7d 08 05 75 5b ba 90 01 02 01 00 6a 10 59 33 c0 8b fa f3 ab 8b fa 6a 01 8d 46 38 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}