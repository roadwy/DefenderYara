
rule TrojanDropper_Win64_FusionBlaze_A_dha{
	meta:
		description = "TrojanDropper:Win64/FusionBlaze.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 72 7a 5f 52 65 73 52 65 6c 65 61 73 65 00 } //01 00 
		$a_01_1 = {5b 2b 5d 20 69 6e 73 2e 65 78 65 20 2d 73 76 63 20 73 76 63 4e 61 6d 65 20 28 69 6e 73 74 61 6c 6c 20 77 69 74 68 20 73 70 65 63 69 66 69 65 64 20 73 76 63 29 00 } //01 00 
		$a_01_2 = {6f 72 7a 5f 53 43 47 65 74 4e 65 74 73 76 63 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}