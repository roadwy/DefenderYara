
rule VirTool_Win64_Callidus_A{
	meta:
		description = "VirTool:Win64/Callidus.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {48 89 5c 24 10 48 89 74 24 18 48 89 7c 24 20 41 57 48 83 ec 50 90 01 07 48 33 c4 48 89 44 24 40 48 8b d9 33 c0 48 89 44 24 20 48 89 44 24 30 48 c7 44 24 38 0f 00 00 00 88 44 24 20 90 01 07 49 c7 c0 ff ff ff ff 66 90 00 } //01 00 
		$a_01_1 = {4f 6e 65 4e 6f 74 65 43 32 2e 64 6c 6c } //01 00  OneNoteC2.dll
		$a_01_2 = {4f 75 74 6c 6f 6f 6b 43 32 2e 64 6c 6c } //01 00  OutlookC2.dll
		$a_01_3 = {54 65 61 6d 73 43 32 2e 64 6c 6c } //00 00  TeamsC2.dll
	condition:
		any of ($a_*)
 
}