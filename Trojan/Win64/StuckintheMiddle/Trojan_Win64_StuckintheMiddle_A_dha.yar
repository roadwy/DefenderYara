
rule Trojan_Win64_StuckintheMiddle_A_dha{
	meta:
		description = "Trojan:Win64/StuckintheMiddle.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 39 45 4c 65 74 78 38 65 4d 52 38 70 64 35 6b 6f 46 61 6d 6f 4f 79 75 66 39 74 54 52 54 50 47 } //01 00  U9ELetx8eMR8pd5koFamoOyuf9tTRTPG
		$a_01_1 = {45 74 77 45 76 65 6e 74 57 72 69 74 65 } //01 00  EtwEventWrite
		$a_01_2 = {6c 69 63 65 6e 73 65 } //01 00  license
		$a_00_3 = {b8 e1 83 0f 3e 41 f7 e3 c1 ea 03 6b c2 21 2b c8 41 0f b6 c0 0f b6 0c 39 03 c8 b8 e1 83 0f 3e f7 e1 c1 ea 03 6b c2 21 2b c8 b8 e1 83 0f 3e 41 f7 e2 44 0f b6 04 39 41 8b ca c1 ea 03 41 ff c2 6b c2 21 } //00 00 
	condition:
		any of ($a_*)
 
}