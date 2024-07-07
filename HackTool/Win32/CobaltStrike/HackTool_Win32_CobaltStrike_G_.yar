
rule HackTool_Win32_CobaltStrike_G_{
	meta:
		description = "HackTool:Win32/CobaltStrike.G!!CobaltStrike.G,SIGNATURE_TYPE_ARHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 00 00 00 00 00 00 00 00 01 90 01 07 01 90 01 07 02 90 01 07 02 90 01 07 01 90 01 0f 03 90 01 07 03 90 00 } //1
		$a_01_1 = {70 3f 00 47 0e 00 00 1c 04 00 00 e0 01 24 00 64 55 55 55 55 56 56 56 56 } //65436
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*65436) >=1
 
}