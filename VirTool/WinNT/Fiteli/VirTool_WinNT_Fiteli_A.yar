
rule VirTool_WinNT_Fiteli_A{
	meta:
		description = "VirTool:WinNT/Fiteli.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {ff 75 b4 ff 75 c4 eb 25 83 f8 02 75 2b 8d 45 9c 50 68 ?? ?? 01 00 e8 ?? ?? ff ff 8b 45 9c 0b 45 a0 } //3
		$a_01_1 = {53 6a 0b ff d6 85 c0 7c 39 8d 73 04 89 75 d4 89 7d e0 8b 45 e0 3b 03 7d 3d 69 c0 1c 01 00 00 } //2
		$a_01_2 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00 54 00 65 00 6e 00 63 00 65 00 6e 00 74 00 5c 00 71 00 71 00 5c 00 71 00 71 00 2e 00 65 00 78 00 65 00 00 00 } //1
		$a_01_3 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 54 00 48 00 49 00 4e 00 4b 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}