
rule HackTool_Win64_Mimikatz_C{
	meta:
		description = "HackTool:Win64/Mimikatz.C,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {6d 00 69 00 6d 00 69 00 6b 00 61 00 74 00 7a 00 20 00 90 02 40 77 00 69 00 74 00 68 00 20 00 6b 00 65 00 6b 00 65 00 6f 00 90 00 } //01 00 
		$a_00_1 = {67 00 65 00 6e 00 74 00 69 00 6c 00 6b 00 69 00 77 00 69 00 2e 00 63 00 6f 00 6d 00 } //01 00  gentilkiwi.com
		$a_00_2 = {42 00 65 00 6e 00 6a 00 61 00 6d 00 69 00 6e 00 20 00 44 00 45 00 4c 00 50 00 59 00 } //00 00  Benjamin DELPY
	condition:
		any of ($a_*)
 
}