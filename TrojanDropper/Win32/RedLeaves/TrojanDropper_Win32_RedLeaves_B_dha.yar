
rule TrojanDropper_Win32_RedLeaves_B_dha{
	meta:
		description = "TrojanDropper:Win32/RedLeaves.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {50 6a 40 ff b5 90 01 02 ff ff 53 ff 15 90 01 03 10 57 e8 90 01 02 00 00 83 c4 04 6a 00 6a 00 6a 00 53 6a 00 6a 00 ff 15 90 01 03 10 50 ff 15 90 01 03 10 68 98 08 00 00 ff 15 90 01 03 10 90 00 } //01 00 
		$a_03_1 = {b8 cd cc cc cc 8b ce f7 e6 c1 ea 03 8d 04 92 03 c0 2b c8 8a 44 0d 90 01 01 2a 44 0d 90 01 01 00 04 1e 46 3b f7 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}