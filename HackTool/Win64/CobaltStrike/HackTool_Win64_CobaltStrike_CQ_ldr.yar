
rule HackTool_Win64_CobaltStrike_CQ_ldr{
	meta:
		description = "HackTool:Win64/CobaltStrike.CQ!ldr,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8d 5c 08 18 48 8d 04 92 48 8d 2c c3 eb } //1
		$a_01_1 = {44 89 ef 45 31 c9 45 31 c0 48 83 c7 22 31 d2 4c 89 e1 4c 8b 7c fd 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}