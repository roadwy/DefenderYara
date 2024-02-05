
rule TrojanDropper_Win64_ClearMarbles_A_dha{
	meta:
		description = "TrojanDropper:Win64/ClearMarbles.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 64 00 "
		
	strings :
		$a_41_0 = {4f ec c4 4e f7 e9 c1 fa 02 8b c2 c1 e8 1f 03 d0 6b d2 0d 8b c1 2b c2 48 98 0f b6 14 18 41 30 10 ff c1 00 } //00 5d 
	condition:
		any of ($a_*)
 
}