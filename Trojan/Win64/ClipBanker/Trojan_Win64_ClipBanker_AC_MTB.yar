
rule Trojan_Win64_ClipBanker_AC_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c1 89 05 90 01 04 eb 90 01 01 8b 44 24 90 01 01 99 83 e2 03 03 c2 83 e0 03 2b c2 8b 0d 90 01 04 03 c8 8b c1 89 44 24 90 01 01 8b 44 24 90 01 01 8b 0d 90 01 04 0b c8 8b c1 89 05 90 01 04 33 d2 8b 44 24 90 01 01 b9 03 00 00 00 f7 f1 8b 0d 90 01 04 03 c8 8b c1 89 44 24 90 01 01 0f be 05 90 01 04 85 c0 75 90 00 } //01 00 
		$a_01_1 = {4e 73 75 32 4f 64 69 77 6f 64 4f 73 32 } //00 00  Nsu2OdiwodOs2
	condition:
		any of ($a_*)
 
}