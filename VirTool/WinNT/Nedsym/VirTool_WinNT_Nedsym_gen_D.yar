
rule VirTool_WinNT_Nedsym_gen_D{
	meta:
		description = "VirTool:WinNT/Nedsym.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 be a0 01 00 00 00 74 25 8d 86 90 90 01 00 00 39 00 74 1b 6a 0c 8d 86 74 01 00 00 68 90 01 04 50 90 00 } //01 00 
		$a_01_1 = {b8 4d 11 86 7c 6a 01 90 68 cd ab 00 00 ff d0 e9 } //01 00 
		$a_01_2 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 4b 00 65 00 72 00 6e 00 65 00 6c 00 45 00 78 00 65 00 63 00 } //00 00 
	condition:
		any of ($a_*)
 
}