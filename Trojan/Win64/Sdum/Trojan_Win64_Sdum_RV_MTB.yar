
rule Trojan_Win64_Sdum_RV_MTB{
	meta:
		description = "Trojan:Win64/Sdum.RV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 28 48 8b 4c 24 08 0f b7 04 48 89 04 24 33 d2 48 8b 44 24 08 b9 05 00 00 00 48 f7 f1 48 8b c2 48 8d 0d f7 87 03 00 0f b7 04 41 8b 0c 24 33 c8 8b c1 48 8b 4c 24 20 48 8b 54 24 08 66 89 04 51 eb a2 } //01 00 
		$a_01_1 = {49 00 6e 00 73 00 74 00 61 00 6e 00 74 00 20 00 56 00 65 00 72 00 69 00 66 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 20 00 54 00 6f 00 6f 00 6c 00 } //00 00  Instant Verification Tool
	condition:
		any of ($a_*)
 
}