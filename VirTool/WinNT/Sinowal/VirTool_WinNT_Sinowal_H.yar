
rule VirTool_WinNT_Sinowal_H{
	meta:
		description = "VirTool:WinNT/Sinowal.H,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {ff 75 10 ff 75 0c ff 55 fc } //01 00 
		$a_01_1 = {50 90 90 58 2b } //01 00 
		$a_01_2 = {57 90 90 5f 2b } //01 00 
		$a_01_3 = {53 5b 2b db 81 c3 } //00 00 
	condition:
		any of ($a_*)
 
}