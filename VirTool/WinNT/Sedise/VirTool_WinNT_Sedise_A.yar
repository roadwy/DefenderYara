
rule VirTool_WinNT_Sedise_A{
	meta:
		description = "VirTool:WinNT/Sedise.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 7d e0 ff 45 dc 83 7d dc 02 0f 8c 4e ff ff ff eb 14 c7 45 d8 06 00 00 80 eb 0b 6a 00 56 ff 75 d0 e8 } //1
		$a_02_1 = {56 ff 75 10 53 ff 75 08 ff 15 ?? ?? 01 00 85 c0 89 45 d4 0f 8c 9e 00 00 00 83 7d 08 05 0f 85 94 00 00 00 83 65 e4 00 85 db 0f 84 88 00 00 00 57 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}