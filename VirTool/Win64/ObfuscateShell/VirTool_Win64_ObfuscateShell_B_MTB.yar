
rule VirTool_Win64_ObfuscateShell_B_MTB{
	meta:
		description = "VirTool:Win64/ObfuscateShell.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 45 dc 8b 45 e0 c1 e0 02 89 45 d8 8b 45 dc c1 f8 04 09 45 d8 48 8b 45 18 48 90 01 03 48 89 55 18 8b 55 d8 88 10 90 00 } //1
		$a_01_1 = {89 45 d0 8b 45 d4 c1 e0 06 25 ff 00 00 00 } //1
		$a_03_2 = {48 89 c1 e8 90 01 04 48 8d 90 01 05 48 89 c1 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}