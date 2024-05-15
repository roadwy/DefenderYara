
rule HackTool_Win32_CobaltStrike_K{
	meta:
		description = "HackTool:Win32/CobaltStrike.K,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 d2 6a 0d 8b c1 5b f7 f3 8a 44 32 0c 30 07 41 } //01 00 
		$a_01_1 = {8b 3b f7 f6 01 cf 41 8a 44 13 0c 30 07 } //00 00 
	condition:
		any of ($a_*)
 
}