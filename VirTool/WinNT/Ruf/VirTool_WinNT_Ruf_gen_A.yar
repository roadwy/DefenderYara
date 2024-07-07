
rule VirTool_WinNT_Ruf_gen_A{
	meta:
		description = "VirTool:WinNT/Ruf.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {6e 00 73 00 6c 00 66 00 75 00 72 00 } //1 nslfur
		$a_01_1 = {5a 77 51 75 65 72 79 56 61 6c 75 65 4b 65 79 00 6e 74 6f 73 6b 72 6e 6c 2e 65 78 65 } //1 睚畑牥噹污敵敋y瑮獯牫汮攮數
		$a_01_2 = {e4 64 a8 02 75 fa c3 b8 00 50 00 00 eb 01 48 0b c0 75 fb c3 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}