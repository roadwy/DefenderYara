
rule HackTool_Win64_CobaltStrike_H{
	meta:
		description = "HackTool:Win64/CobaltStrike.H,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {4d 5a 41 52 55 48 89 e5 48 81 ec 20 00 00 00 48 8d 1d ea ff ff ff 48 89 df 48 81 c3 90 01 04 ff d3 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}