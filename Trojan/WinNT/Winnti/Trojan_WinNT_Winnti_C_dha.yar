
rule Trojan_WinNT_Winnti_C_dha{
	meta:
		description = "Trojan:WinNT/Winnti.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 00 6d 00 61 00 6c 00 6c 00 65 00 64 00 2e 00 66 00 6f 00 6e 00 } //01 00  smalled.fon
		$a_01_1 = {57 ff d3 83 c4 0c 33 d2 66 89 97 fe 01 00 00 33 c0 56 89 } //01 00 
		$a_01_2 = {56 ff d3 33 c9 8d be 00 04 00 00 83 c4 0c 66 89 8e fe 01 00 00 85 ff 74 19 } //00 00 
	condition:
		any of ($a_*)
 
}