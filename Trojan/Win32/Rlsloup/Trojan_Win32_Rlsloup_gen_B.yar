
rule Trojan_Win32_Rlsloup_gen_B{
	meta:
		description = "Trojan:Win32/Rlsloup.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {74 26 68 0e 00 00 c0 68 90 01 04 e8 90 01 02 ff ff 83 c4 08 53 6a 12 90 00 } //01 00 
		$a_03_1 = {eb 25 3d 5c 3f 3f 5c 75 0f 8d 84 24 90 01 02 00 00 50 8d 4c 24 90 01 01 51 eb 0d 8d 94 24 90 01 02 00 00 52 8d 44 24 90 01 01 50 ff d5 90 00 } //01 00 
		$a_01_2 = {8b 7a 3c 03 fa c7 47 58 00 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}