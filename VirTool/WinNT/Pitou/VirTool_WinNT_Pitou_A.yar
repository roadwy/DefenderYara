
rule VirTool_WinNT_Pitou_A{
	meta:
		description = "VirTool:WinNT/Pitou.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {9c 56 57 50 53 51 52 e8 90 01 04 8f 46 08 8f 46 04 8f 46 0c 8f 06 8f 46 1c 8f 46 18 8f 46 20 58 3b 05 80 54 47 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}