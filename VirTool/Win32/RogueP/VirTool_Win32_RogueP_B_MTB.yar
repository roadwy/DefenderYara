
rule VirTool_Win32_RogueP_B_MTB{
	meta:
		description = "VirTool:Win32/RogueP.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 8b 16 48 8b 4d 90 01 07 8b fb 48 8b ce 85 c0 b8 01 00 00 00 0f 45 f8 e8 90 01 04 48 8b 4d 90 00 } //01 00 
		$a_03_1 = {85 ff 0f 84 3b 01 00 00 48 8b 4d 88 ff 90 01 05 85 c0 0f 84 29 01 00 00 ff 90 01 05 8b d0 48 8d 90 01 05 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}