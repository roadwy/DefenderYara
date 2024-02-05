
rule HackTool_Win64_MimikatzPacker_SA_MTB{
	meta:
		description = "HackTool:Win64/MimikatzPacker.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 8b cf e8 90 01 04 85 c0 74 90 01 01 0f b7 44 2e 90 01 01 48 83 c7 90 01 01 ff c3 3b d8 76 90 00 } //01 00 
		$a_03_1 = {0f b6 04 1f 30 03 48 ff c3 48 83 e9 90 01 01 75 90 01 01 48 83 ef 90 01 01 0f 29 84 24 90 01 04 48 83 ee 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}