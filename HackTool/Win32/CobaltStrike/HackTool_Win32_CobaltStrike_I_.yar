
rule HackTool_Win32_CobaltStrike_I_{
	meta:
		description = "HackTool:Win32/CobaltStrike.I!!CobaltStrike.I,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 04 ca 8b 54 ca 04 c3 e8 90 01 04 66 83 f8 90 00 } //01 00 
		$a_03_1 = {8a 10 40 84 d2 75 90 01 04 8b 15 90 01 04 e9 90 01 02 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}