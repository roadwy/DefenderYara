
rule Trojan_Win32_TurtleLoader_PAL_dha{
	meta:
		description = "Trojan:Win32/TurtleLoader.PAL!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 00 41 00 59 00 4c 00 4f 00 41 00 44 00 } //01 00  PAYLOAD
		$a_00_1 = {49 6e 69 74 69 61 74 65 54 68 65 41 74 74 61 63 6b } //01 00  InitiateTheAttack
		$a_00_2 = {44 6c 6c 4c 6f 61 64 65 72 } //01 00  DllLoader
		$a_00_3 = {52 65 70 6c 61 63 65 20 77 69 74 68 20 79 6f 75 72 20 70 61 79 6c 6f 61 64 20 66 69 6c 65 } //00 00  Replace with your payload file
	condition:
		any of ($a_*)
 
}