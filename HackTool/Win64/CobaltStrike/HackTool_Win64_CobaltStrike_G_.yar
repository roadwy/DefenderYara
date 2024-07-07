
rule HackTool_Win64_CobaltStrike_G_{
	meta:
		description = "HackTool:Win64/CobaltStrike.G!!CobaltStrike.G64,SIGNATURE_TYPE_ARHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 90 01 0f 01 90 01 0f 02 90 01 0f 02 90 01 0f 01 90 01 1f 03 90 01 0f 03 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}