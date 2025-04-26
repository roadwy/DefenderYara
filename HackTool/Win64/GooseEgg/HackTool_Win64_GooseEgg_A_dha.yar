
rule HackTool_Win64_GooseEgg_A_dha{
	meta:
		description = "HackTool:Win64/GooseEgg.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 "
		
	strings :
		$a_43_0 = {16 35 0c c7 45 90 01 01 24 4a c6 4f c7 45 90 01 01 c5 23 94 2b c7 45 90 01 01 1e ca 65 aa 90 00 00 } //100
	condition:
		((#a_43_0  & 1)*100) >=100
 
}