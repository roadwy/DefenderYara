
rule Trojan_WinNT_Lechiket_A{
	meta:
		description = "Trojan:WinNT/Lechiket.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 45 54 20 2f 25 73 3f 26 69 64 3d 25 73 26 6d 61 72 6b 3d 25 73 } //01 00  GET /%s?&id=%s&mark=%s
		$a_01_1 = {73 72 76 2e 70 68 70 } //01 00  srv.php
		$a_01_2 = {5b 4e 45 54 57 4f 52 4b 20 44 41 54 41 3a 5d } //01 00  [NETWORK DATA:]
		$a_01_3 = {53 45 52 56 45 52 49 53 4f 4b } //01 00  SERVERISOK
		$a_03_4 = {80 c2 61 88 14 0e 46 83 fe 08 72 e2 c6 04 0e 00 b8 23 34 22 00 8b f9 4f f6 c3 01 74 0f 8a 47 01 47 84 c0 75 f8 be 90 01 04 eb 0d 8a 47 01 47 84 c0 75 f8 be 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}