
rule HackTool_Win64_CobaltStrike_K_{
	meta:
		description = "HackTool:Win64/CobaltStrike.K!!CobaltStrike.K64,SIGNATURE_TYPE_ARHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 f7 e1 41 8b c1 c1 ea 02 41 ff c1 6b d2 0d 2b c2 } //1
		$a_01_1 = {4c 8b 19 41 f7 f2 4d 01 cb 49 ff c1 89 d0 8a 44 01 18 41 30 03 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}