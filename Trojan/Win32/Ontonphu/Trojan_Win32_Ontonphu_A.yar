
rule Trojan_Win32_Ontonphu_A{
	meta:
		description = "Trojan:Win32/Ontonphu.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 2e 3a 3a 3a 46 72 65 65 5f 53 6f 66 74 77 61 72 65 3a 3a 3a 2e 2e } //01 00  ..:::Free_Software:::..
		$a_01_1 = {48 54 54 50 53 3a 2f 2f 00 } //01 00 
		$a_00_2 = {6d 65 6d 62 65 72 6c 69 73 74 2e 70 68 70 3f 6d 6f 64 65 3d 76 69 65 77 70 72 6f 66 69 6c 65 26 75 3d } //01 00  memberlist.php?mode=viewprofile&u=
		$a_00_3 = {57 00 65 00 62 00 4d 00 6f 00 6e 00 65 00 79 00 } //01 00  WebMoney
		$a_00_4 = {50 8b 13 8b 0f b8 02 00 00 80 e8 } //00 00 
	condition:
		any of ($a_*)
 
}