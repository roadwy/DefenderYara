
rule HackTool_Win64_Inject_SX_MTB{
	meta:
		description = "HackTool:Win64/Inject.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 01 48 8b 0d da 54 0d ?? ?? ?? ?? 89 0a f3 0f 6f 05 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 41 0f 11 00 f3 0f 6f 0d ?? ?? ?? ?? 41 0f 11 48 10 49 89 01 8b 05 ?? ?? ?? ?? 41 89 41 08 31 c0 } //15
		$a_01_1 = {66 0f 7e ca 66 0f 6f c1 48 8b 84 24 e8 00 00 00 48 2b 84 24 e0 00 00 00 48 89 84 24 90 00 00 00 66 49 0f 6e ec 44 89 e0 48 8d 34 12 66 0f 6c c5 48 8d 54 06 08 48 8d 8c 24 e0 00 00 00 48 89 84 24 88 00 00 00 0f c6 c0 e8 66 0f d6 84 24 98 00 00 00 } //10
	condition:
		((#a_03_0  & 1)*15+(#a_01_1  & 1)*10) >=25
 
}