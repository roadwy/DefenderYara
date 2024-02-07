
rule Trojan_Win32_Claretore_gen_A{
	meta:
		description = "Trojan:Win32/Claretore.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 1b 8b 4d 0c 8b 46 3c 3b cb 74 0d 66 8b 44 30 16 66 c1 e8 0d 24 01 88 01 c6 45 ff 01 } //01 00 
		$a_03_1 = {50 0f 31 50 68 90 01 04 8d 44 24 7c 6a 40 50 90 00 } //01 00 
		$a_01_2 = {24 6d 69 64 3d 25 53 26 75 69 64 3d 25 64 26 76 65 72 73 69 6f 6e 3d 25 73 24 } //00 00  $mid=%S&uid=%d&version=%s$
	condition:
		any of ($a_*)
 
}