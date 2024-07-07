
rule VirTool_WinNT_Drvheed_A{
	meta:
		description = "VirTool:WinNT/Drvheed.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c6 06 68 89 7e 01 c6 46 05 c3 } //1
		$a_01_1 = {0f 20 c0 25 ff ff fe ff 0f 22 c0 } //1
		$a_01_2 = {81 20 ff ff ff fd 0f b7 56 06 83 c0 28 41 3b ca 72 ee } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule VirTool_WinNT_Drvheed_A_2{
	meta:
		description = "VirTool:WinNT/Drvheed.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {0f 20 e0 c3 } //1
		$a_01_1 = {0f 20 c0 25 ff ff fe ff 0f 22 c0 c2 04 00 0f 20 c0 0d 00 00 01 00 0f 22 c0 c2 04 00 } //1
		$a_01_2 = {8b 48 3c 03 c8 8b 49 50 bb 00 f0 ff ff bf 00 10 00 00 f7 c1 ff 0f 00 00 74 04 23 cb 03 cf } //1
		$a_01_3 = {83 c4 24 a9 ff ff 1f 00 74 0a 25 00 00 e0 ff 05 00 00 20 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}