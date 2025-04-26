
rule HackTool_Win64_MimikatzPacker_SA_MTB{
	meta:
		description = "HackTool:Win64/MimikatzPacker.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b cf e8 ?? ?? ?? ?? 85 c0 74 ?? 0f b7 44 2e ?? 48 83 c7 ?? ff c3 3b d8 76 } //1
		$a_03_1 = {0f b6 04 1f 30 03 48 ff c3 48 83 e9 ?? 75 ?? 48 83 ef ?? 0f 29 84 24 ?? ?? ?? ?? 48 83 ee ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}