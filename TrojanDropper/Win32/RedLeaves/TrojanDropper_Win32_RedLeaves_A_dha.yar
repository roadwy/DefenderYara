
rule TrojanDropper_Win32_RedLeaves_A_dha{
	meta:
		description = "TrojanDropper:Win32/RedLeaves.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {32 0c 3a 83 c2 02 88 0e 83 fa 08 7c 90 01 01 eb 90 01 01 ba 08 00 00 00 32 0c 3a 83 c2 02 88 0e 83 fa 10 90 00 } //01 00 
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //00 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	condition:
		any of ($a_*)
 
}