
rule VirTool_WinNT_Idicaf_A{
	meta:
		description = "VirTool:WinNT/Idicaf.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {50 00 66 c7 45 90 01 01 68 00 66 c7 45 90 01 01 79 00 66 c7 45 90 01 01 73 00 90 00 } //02 00 
		$a_03_1 = {68 42 52 69 6e 56 6a 00 ff 15 90 01 04 8b f8 85 ff 74 31 8d 45 fc 50 56 57 ff 75 08 ff 15 90 00 } //01 00 
		$a_03_2 = {eb 37 60 8b c0 61 e8 90 01 02 ff ff a1 90 01 04 8b 40 01 8b 0d 90 01 04 8b 55 f8 89 0c 82 83 25 90 01 04 00 fb 90 00 } //01 00 
		$a_01_3 = {42 72 65 61 6b 49 6e 2e 70 64 62 00 } //00 00 
	condition:
		any of ($a_*)
 
}