
rule VirTool_WinNT_Rootkitdrv_LX{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.LX,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {57 56 8b 78 18 8b 70 48 39 7e 18 74 04 8b 36 eb f7 68 90 01 02 01 00 ba 90 01 02 01 00 39 3a 0f 85 90 01 04 74 05 60 8b 74 24 24 8b 7c 24 28 fc b2 80 33 db a4 b3 02 90 00 } //01 00 
		$a_01_1 = {6a 64 59 33 c0 66 81 3a c6 05 75 13 66 81 7a 06 01 e8 75 0b 83 c2 08 8b 02 8d 44 10 04 } //00 00 
	condition:
		any of ($a_*)
 
}