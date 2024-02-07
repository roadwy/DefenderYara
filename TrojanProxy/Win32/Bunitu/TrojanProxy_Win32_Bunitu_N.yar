
rule TrojanProxy_Win32_Bunitu_N{
	meta:
		description = "TrojanProxy:Win32/Bunitu.N,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {80 7f 10 33 75 20 33 c0 68 90 01 04 50 ff 77 11 68 90 01 04 ff 04 24 90 00 } //01 00 
		$a_03_1 = {b2 6e 86 d6 88 70 04 b2 65 86 d6 88 70 08 51 b9 90 01 04 87 d1 29 10 59 90 00 } //01 00 
		$a_01_2 = {83 c0 78 83 c0 78 c1 e8 0a 56 be 3c 00 00 00 3b c6 72 10 83 e8 1e 83 e8 1e 41 3b ce 75 03 } //01 00 
		$a_03_3 = {4a 0b d2 75 11 0f 31 0f b6 c0 c1 e0 02 bf 90 01 04 03 f8 eb 05 83 3f 00 75 e5 90 00 } //00 00 
		$a_00_4 = {7e 15 } //00 00  ᕾ
	condition:
		any of ($a_*)
 
}