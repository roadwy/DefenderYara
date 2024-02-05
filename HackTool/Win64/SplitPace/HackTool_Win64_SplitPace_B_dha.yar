
rule HackTool_Win64_SplitPace_B_dha{
	meta:
		description = "HackTool:Win64/SplitPace.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 64 00 "
		
	strings :
		$a_01_0 = {49 83 f8 0a 75 29 48 be 64 69 73 63 6f 6e 6e 65 0f 1f 84 00 00 00 00 00 48 39 37 0f 85 07 fe ff ff } //00 00 
	condition:
		any of ($a_*)
 
}