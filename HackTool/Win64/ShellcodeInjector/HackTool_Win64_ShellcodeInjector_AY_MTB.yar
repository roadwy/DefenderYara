
rule HackTool_Win64_ShellcodeInjector_AY_MTB{
	meta:
		description = "HackTool:Win64/ShellcodeInjector.AY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 14 99 48 ff c3 48 3b d8 72 90 01 01 48 8b 5c 24 90 01 01 48 8d 04 85 90 01 04 49 3b c1 73 90 01 01 0f 1f 00 30 14 08 48 ff c0 49 3b c1 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}