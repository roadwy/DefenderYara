
rule VirTool_WinNT_Kelzef_C{
	meta:
		description = "VirTool:WinNT/Kelzef.C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_11_0 = {65 74 00 73 74 61 72 74 20 6e 65 77 64 72 69 76 65 72 00 01 } //00 1a 
		$a_53_1 = {46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 } //5c 44 
		$a_44_2 = {72 70 00 01 00 0d 11 5c 67 69 67 61 6c 61 6e 2e 74 78 74 00 01 00 13 11 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 37 00 01 00 10 11 5f 65 77 64 72 69 76 65 72 00 2d 6c 69 6e 6b 00 00 00 03 00 5d } //04 00 
	condition:
		any of ($a_*)
 
}