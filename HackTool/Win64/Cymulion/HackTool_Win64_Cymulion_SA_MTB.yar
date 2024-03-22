
rule HackTool_Win64_Cymulion_SA_MTB{
	meta:
		description = "HackTool:Win64/Cymulion.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 8b c2 48 8d 0c 2a 83 e0 90 01 01 48 ff c2 0f b6 84 18 90 01 04 32 04 0e 88 01 49 3b d6 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}