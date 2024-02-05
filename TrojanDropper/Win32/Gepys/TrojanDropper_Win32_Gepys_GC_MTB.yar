
rule TrojanDropper_Win32_Gepys_GC_MTB{
	meta:
		description = "TrojanDropper:Win32/Gepys.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {89 f9 89 f2 d3 e2 01 d7 f7 e7 89 45 90 01 01 a3 90 0a 30 00 a3 90 01 04 8b 3d 90 01 04 b8 90 00 } //01 00 
		$a_00_1 = {8b 55 08 8b 4d 0c 8a 02 88 45 ff 8a 01 88 02 8a 45 ff 88 01 } //00 00 
	condition:
		any of ($a_*)
 
}