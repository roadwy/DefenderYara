
rule VirTool_Win32_RogueP_A_MTB{
	meta:
		description = "VirTool:Win32/RogueP.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 6f 63 61 6c 68 6f 73 74 2f 70 69 70 65 2f 25 73 5b 5c 70 69 70 65 5c 65 70 6d 61 70 70 65 72 5d } //01 00 
		$a_03_1 = {48 8b d5 48 8d 0d 19 9f 01 00 e8 90 01 04 45 33 c0 ba d2 04 00 00 41 8d 48 01 ff 90 01 05 85 c0 74 13 48 8d 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}