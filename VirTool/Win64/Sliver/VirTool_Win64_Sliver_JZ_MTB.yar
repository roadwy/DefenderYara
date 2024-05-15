
rule VirTool_Win64_Sliver_JZ_MTB{
	meta:
		description = "VirTool:Win64/Sliver.JZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {45 8b 04 02 83 c1 90 01 01 0b 53 90 01 01 49 83 c2 90 01 01 03 53 90 01 01 44 0f af 83 90 01 04 03 ca 8b 83 90 01 04 2b 43 90 01 01 2d 90 01 04 89 4b 90 01 01 31 43 90 01 01 48 63 8b 90 00 } //01 00 
		$a_03_1 = {44 88 04 01 8b 43 90 01 01 ff 83 90 01 04 83 f0 90 01 01 01 43 90 01 01 49 81 fa 90 01 04 0f 8c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}