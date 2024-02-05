
rule HackTool_Win64_GooseEgg_B_dha{
	meta:
		description = "HackTool:Win64/GooseEgg.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 64 00 "
		
	strings :
		$a_43_0 = {15 cd 5b 07 90 01 07 34 4f 90 01 07 34 7b 90 00 00 } //00 5d 
	condition:
		any of ($a_*)
 
}