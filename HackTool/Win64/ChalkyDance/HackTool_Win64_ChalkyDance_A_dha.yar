
rule HackTool_Win64_ChalkyDance_A_dha{
	meta:
		description = "HackTool:Win64/ChalkyDance.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_42_0 = {8b 40 30 ba 90 01 01 00 00 00 b9 40 00 00 00 41 ff d0 90 00 00 } //10
	condition:
		((#a_42_0  & 1)*10) >=10
 
}