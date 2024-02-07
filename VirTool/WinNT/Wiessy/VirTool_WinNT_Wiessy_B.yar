
rule VirTool_WinNT_Wiessy_B{
	meta:
		description = "VirTool:WinNT/Wiessy.B,SIGNATURE_TYPE_PEHSTR_EXT,09 00 08 00 05 00 00 03 00 "
		
	strings :
		$a_01_0 = {c7 06 8b ff 55 8b c6 46 04 ec 0f 20 c0 0d 00 00 01 00 } //03 00 
		$a_01_1 = {75 47 e8 f2 fd ff ff 84 c0 0f 84 98 02 00 00 8d 45 e0 } //02 00 
		$a_01_2 = {5c 44 65 76 69 63 65 5c 48 61 72 64 64 69 73 6b 30 5c 44 52 30 00 } //01 00  䑜癥捩履慈摲楤歳尰剄0
		$a_01_3 = {5c 44 6f 73 44 65 76 69 63 65 73 5c 45 43 61 74 44 69 73 6b 31 00 } //01 00  䑜獯敄楶散屳䍅瑡楄歳1
		$a_01_4 = {5c 44 65 76 69 63 65 5c 45 43 61 74 44 69 73 6b 30 00 } //00 00  䑜癥捩履䍅瑡楄歳0
	condition:
		any of ($a_*)
 
}