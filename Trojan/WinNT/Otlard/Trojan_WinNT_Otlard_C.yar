
rule Trojan_WinNT_Otlard_C{
	meta:
		description = "Trojan:WinNT/Otlard.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 47 6f 6f 74 } //01 00 
		$a_01_1 = {8b 4d f8 0f b6 11 83 fa 55 75 ec } //01 00 
		$a_01_2 = {be 85 00 00 00 f7 fe 6b d2 03 03 ca 81 e1 ff 00 00 00 88 8d } //01 00 
		$a_01_3 = {b8 22 00 00 c0 eb 3a 83 7d fc 00 75 04 33 c0 eb 30 68 } //00 00 
	condition:
		any of ($a_*)
 
}