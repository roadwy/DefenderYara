
rule VirTool_WinNT_Kelzef_A{
	meta:
		description = "VirTool:WinNT/Kelzef.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 6d 6b 64 72 76 2e 70 64 62 00 } //01 00 
		$a_01_1 = {67 69 67 61 6c 61 6e 2e 73 79 73 00 } //01 00 
		$a_01_2 = {4b 4c 5a 20 46 49 4c 45 20 46 4f 55 4e 44 21 20 25 53 00 } //01 00 
		$a_01_3 = {5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 65 00 74 00 63 00 5c 00 68 00 6f 00 73 00 74 00 37 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}