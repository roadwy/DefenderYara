
rule VirTool_WinNT_Chksyn_B{
	meta:
		description = "VirTool:WinNT/Chksyn.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {75 45 83 7d 08 05 75 3f 33 ff 85 f6 74 39 03 36 0f b7 46 38 83 f8 04 7c 27 6a 04 68 90 01 02 01 00 ff 76 3c e8 90 00 } //01 00 
		$a_01_1 = {75 c0 eb 10 85 db 74 05 83 23 00 eb 07 c7 45 30 06 00 00 80 } //01 00 
	condition:
		any of ($a_*)
 
}