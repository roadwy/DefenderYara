
rule VirTool_WinNT_Jadtre_C{
	meta:
		description = "VirTool:WinNT/Jadtre.C,SIGNATURE_TYPE_PEHSTR_EXT,14 00 0f 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 47 00 75 00 6e 00 74 00 69 00 6f 00 72 00 00 00 } //05 00 
		$a_01_1 = {ba 55 aa 00 00 66 39 90 fe 01 00 00 75 21 81 b8 a2 01 00 00 11 22 33 44 75 15 } //05 00 
		$a_03_2 = {83 ce ff 68 f6 03 00 00 68 f0 01 00 00 e8 90 01 02 ff ff 3c 01 74 22 ff 75 08 68 76 03 00 00 68 70 01 00 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}