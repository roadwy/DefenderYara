
rule Trojan_WinNT_Alureon_C{
	meta:
		description = "Trojan:WinNT/Alureon.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 08 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 81 38 4d 5a 0f 84 90 01 02 00 00 48 90 00 } //01 00 
		$a_01_1 = {81 c1 00 02 00 00 8b 09 } //01 00 
		$a_01_2 = {0f 01 0c 24 ff 74 24 02 } //01 00 
		$a_01_3 = {ad 33 c2 ab } //01 00 
		$a_01_4 = {94 c8 37 09 } //01 00 
		$a_01_5 = {a2 b3 45 5e } //01 00 
		$a_01_6 = {bb 64 0b 73 } //01 00 
		$a_01_7 = {c4 e8 40 4c } //00 00 
	condition:
		any of ($a_*)
 
}