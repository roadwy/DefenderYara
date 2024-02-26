
rule HackTool_Win64_CobaltStrike_K{
	meta:
		description = "HackTool:Win64/CobaltStrike.K,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff ee ff ee 00 00 00 00 90 01 28 ff ef fd ff ff 7f 00 00 90 01 38 f0 ff ff ff ff ff ff ff 90 01 18 18 90 01 0f e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}