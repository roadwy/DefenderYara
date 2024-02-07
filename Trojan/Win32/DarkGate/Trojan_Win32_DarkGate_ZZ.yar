
rule Trojan_Win32_DarkGate_ZZ{
	meta:
		description = "Trojan:Win32/DarkGate.ZZ,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //0a 00 
		$a_81_1 = {5f 5f 5f 5f 70 61 64 6f 72 75 5f 5f 5f 5f } //0a 00  ____padoru____
		$a_81_2 = {45 72 72 6f 72 3a 20 6e 6f 20 64 65 6c 69 6d 69 74 61 64 6f 72 20 6d 6f 6e 69 74 6f 72 } //0a 00  Error: no delimitador monitor
		$a_81_3 = {68 76 6e 63 20 65 72 72 6f 72 } //0a 00  hvnc error
		$a_81_4 = {2d 61 63 63 65 70 74 65 75 6c 61 20 2d 64 20 2d 75 20 } //00 00  -accepteula -d -u 
		$a_00_5 = {7a 08 00 00 00 00 00 00 00 00 00 00 5d 04 00 00 f1 3b 06 80 5c 27 00 00 f2 3b 06 80 00 00 01 00 08 00 11 00 ac 21 44 61 } //72 6b 
	condition:
		any of ($a_*)
 
}