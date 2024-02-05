
rule HackTool_Win64_CobaltStrike_G{
	meta:
		description = "HackTool:Win64/CobaltStrike.G,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 90 01 0f 01 90 01 0f 02 90 01 0f 02 90 01 0f 01 90 01 1f 03 90 01 0f 03 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}