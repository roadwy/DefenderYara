
rule VirTool_WinNT_Ursnif_B{
	meta:
		description = "VirTool:WinNT/Ursnif.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 0d 90 01 02 14 00 a1 90 01 02 14 00 8b 40 01 8b 09 8b 35 90 01 02 14 00 8d 0c 81 ba 90 01 02 14 00 ff d6 90 00 } //2
		$a_03_1 = {c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 eb 5c 39 0d 90 01 02 14 00 75 54 68 57 64 6d 20 57 6a 01 90 00 } //2
		$a_01_2 = {5c 68 69 64 65 5f 65 76 72 32 2e 70 64 62 } //1 \hide_evr2.pdb
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=3
 
}