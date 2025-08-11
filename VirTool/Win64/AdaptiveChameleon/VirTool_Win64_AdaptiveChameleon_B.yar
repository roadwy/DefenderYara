
rule VirTool_Win64_AdaptiveChameleon_B{
	meta:
		description = "VirTool:Win64/AdaptiveChameleon.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 10 0f ca 89 d1 48 8b 44 24 28 48 8b 5c 24 30 e8 ?? ?? ?? ?? 48 83 c4 18 5d } //1
		$a_03_1 = {48 8b 08 48 8b 44 24 58 48 8b 5c 24 40 41 b8 ?? ?? ?? ?? e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}