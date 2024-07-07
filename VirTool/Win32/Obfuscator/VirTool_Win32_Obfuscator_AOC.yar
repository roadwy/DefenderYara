
rule VirTool_Win32_Obfuscator_AOC{
	meta:
		description = "VirTool:Win32/Obfuscator.AOC,SIGNATURE_TYPE_PEHSTR_EXT,07 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8a 0c 31 32 cb 85 d2 8b 55 fc 74 05 88 0c 32 eb 06 } //1
		$a_01_1 = {8a 0c 11 32 cb 85 ff 74 08 8b 75 fc 88 0c 16 eb 06 8b 4d fc 88 14 11 } //1
		$a_01_2 = {68 00 70 01 00 6a 08 52 ff d3 } //1
		$a_01_3 = {5c 4c 6f 74 5c 70 72 6f 76 69 64 65 73 5c 74 65 6d 70 6f 72 61 72 79 5c 55 52 49 5c 6d 69 74 69 2e 70 64 62 } //3 \Lot\provides\temporary\URI\miti.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*3) >=4
 
}