
rule Trojan_Win64_ShellCodeRunner_GVD_MTB{
	meta:
		description = "Trojan:Win64/ShellCodeRunner.GVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 0f af ce f7 e9 03 d1 c1 fa 07 8b c2 c1 e8 1f 03 d0 b8 81 80 80 80 42 88 54 03 01 42 0f b6 4c 03 02 41 0f af ce f7 e9 03 d1 c1 fa 07 8b c2 c1 e8 1f 03 d0 42 88 54 03 02 49 83 c0 04 4c 3b c7 72 93 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}