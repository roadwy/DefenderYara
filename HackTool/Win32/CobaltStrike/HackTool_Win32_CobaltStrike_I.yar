
rule HackTool_Win32_CobaltStrike_I{
	meta:
		description = "HackTool:Win32/CobaltStrike.I,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 04 ca 8b 54 ca 04 c3 e8 ?? ?? ?? ?? 66 83 f8 } //1
		$a_03_1 = {8a 10 40 84 d2 75 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? e9 ?? ?? ff ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}