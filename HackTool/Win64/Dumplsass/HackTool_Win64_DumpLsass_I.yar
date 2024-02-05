
rule HackTool_Win64_DumpLsass_I{
	meta:
		description = "HackTool:Win64/DumpLsass.I,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_00_0 = {5c 00 64 00 75 00 6d 00 70 00 36 00 34 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}