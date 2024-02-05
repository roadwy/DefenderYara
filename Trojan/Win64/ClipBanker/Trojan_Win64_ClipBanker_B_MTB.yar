
rule Trojan_Win64_ClipBanker_B_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {66 83 f8 62 75 74 0f b7 43 02 66 83 f8 63 75 43 66 83 7b 04 31 0f 85 d4 00 00 00 0f b7 43 06 66 83 f8 71 75 12 48 8d 05 14 46 00 00 48 8b 5c 24 30 48 83 c4 20 5f c3 } //01 00 
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //00 00 
	condition:
		any of ($a_*)
 
}