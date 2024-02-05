
rule HackTool_Win64_Mimikatz_B{
	meta:
		description = "HackTool:Win64/Mimikatz.B,SIGNATURE_TYPE_PEHSTR,14 00 14 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {f6 46 24 02 0f 84 00 00 } //0a 00 
		$a_01_1 = {f6 46 24 0a 0f 84 00 00 } //0a 00 
		$a_01_2 = {f6 45 24 02 0f 84 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}