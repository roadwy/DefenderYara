
rule Trojan_Win64_SunSpot_A_dha{
	meta:
		description = "Trojan:Win64/SunSpot.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {fc f3 2a 83 e5 f6 d0 24 90 01 01 bf ce 88 30 c2 48 e7 90 00 } //01 00 
		$a_03_1 = {81 8c 85 49 b9 00 06 78 0b e9 90 01 01 60 26 64 b2 da 90 00 } //f6 ff 
		$a_03_2 = {57 6f 72 6c 64 20 6f 90 01 01 20 57 61 72 63 72 61 66 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}