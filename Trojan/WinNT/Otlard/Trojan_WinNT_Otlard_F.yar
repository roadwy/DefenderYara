
rule Trojan_WinNT_Otlard_F{
	meta:
		description = "Trojan:WinNT/Otlard.F,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 55 fc 03 95 00 ff ff ff 81 7a fc 37 13 d3 a0 74 } //01 00 
		$a_01_1 = {b8 22 00 00 c0 eb 38 83 7d fc 00 75 04 33 c0 eb 2e 68 } //01 00 
		$a_01_2 = {c6 45 e8 83 c6 45 e9 ec c6 45 ea 04 c6 45 eb c7 c6 45 ec 04 c6 45 ed 24 } //01 00 
		$a_01_3 = {47 6f 6f 74 6b 69 74 } //00 00 
	condition:
		any of ($a_*)
 
}