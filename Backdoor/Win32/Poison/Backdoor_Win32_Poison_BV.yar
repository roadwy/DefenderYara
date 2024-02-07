
rule Backdoor_Win32_Poison_BV{
	meta:
		description = "Backdoor:Win32/Poison.BV,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 6f 66 74 5c 6d 6f 76 65 2e 62 61 6b } //01 00  soft\move.bak
		$a_01_1 = {74 5c 74 65 6d 70 66 69 6c 65 2e 62 61 6b } //01 00  t\tempfile.bak
		$a_03_2 = {61 72 64 2e 65 78 65 00 90 02 02 61 76 67 75 00 90 00 } //01 00 
		$a_03_3 = {83 c9 ff f2 ae f7 d1 2b f9 6a 03 8b f7 8b d9 8b fa 83 c9 ff f2 ae 8b cb 4f c1 e9 02 f3 a5 8b cb 50 83 e1 03 6a 01 8d 90 02 06 68 00 00 00 80 f3 a4 50 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}