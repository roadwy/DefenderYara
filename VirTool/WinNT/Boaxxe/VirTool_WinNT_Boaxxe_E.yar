
rule VirTool_WinNT_Boaxxe_E{
	meta:
		description = "VirTool:WinNT/Boaxxe.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {83 e9 05 80 38 55 89 4d 08 75 61 66 81 78 01 8b ec 75 59 66 81 78 03 83 ec 75 51 80 78 05 14 75 4b 6a 01 68 } //1
		$a_02_1 = {6a 0b ff d3 8b 45 90 01 01 89 46 1c 90 09 0a 00 72 90 01 01 8d 4d 90 01 01 51 50 ff 90 01 01 0c 90 01 0a 90 03 04 04 eb 90 01 01 e9 90 01 04 8b 4e 0c 89 01 89 7e 1c 90 03 01 01 eb e9 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}