
rule Trojan_Win32_MoriAgent_A_dha{
	meta:
		description = "Trojan:Win32/MoriAgent.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {7c 78 37 64 38 37 33 69 71 71 } //01 00  |x7d873iqq
		$a_01_1 = {6c 6a 79 66 69 69 77 6e 73 6b 74 } //01 00  ljyfiiwnskt
		$a_01_2 = {68 74 73 73 6a 68 79 } //01 00  htssjhy
		$a_01_3 = {6b 77 6a 6a 66 69 69 77 6e 73 6b 74 } //01 00  kwjjfiiwnskt
		$a_01_4 = {68 71 74 78 6a 78 74 68 70 6a 79 } //01 00  hqtxjxthpjy
		$a_01_5 = {5c 58 46 58 79 66 77 79 7a 75 } //01 00  \XFXyfwyzu
		$a_01_6 = {5c 58 46 48 71 6a 66 73 7a 75 } //01 00  \XFHqjfszu
		$a_01_7 = {5a 6d 69 6c 58 7a 77 6b 6d 7b 7b 55 6d 75 77 7a } //01 00  ZmilXzwkm{{Umuwz
		$a_01_8 = {5e 71 7a 7c 7d 69 74 58 7a 77 7c 6d 6b 7c } //01 00  ^qz|}itXzw|mk|
		$a_01_9 = {5f 7a 71 7c 6d 58 7a 77 6b 6d 7b 7b 55 6d 75 77 7a } //00 00  _zq|mXzwkm{{Umuwz
	condition:
		any of ($a_*)
 
}