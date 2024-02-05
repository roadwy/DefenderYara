
rule Trojan_WinNT_Jinto_A{
	meta:
		description = "Trojan:WinNT/Jinto.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {1b c0 83 d8 ff 85 c0 75 90 01 01 8b 4c 24 0c 0f b7 14 79 89 54 24 1c 47 3b 7c 24 10 72 90 00 } //01 00 
		$a_02_1 = {56 57 ff 15 90 01 04 8b f8 33 f6 8d 64 24 00 6a 07 8d 04 3e 68 90 01 04 50 e8 90 01 04 83 c4 0c 85 c0 74 90 01 01 46 81 fe 00 10 00 00 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}