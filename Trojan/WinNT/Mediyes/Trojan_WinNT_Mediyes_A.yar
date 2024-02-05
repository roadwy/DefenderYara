
rule Trojan_WinNT_Mediyes_A{
	meta:
		description = "Trojan:WinNT/Mediyes.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 4d f8 8b 45 f4 c1 e1 02 8d 14 01 8b 02 8b 00 89 02 8b 55 f4 8b 0c 11 eb } //01 00 
		$a_01_1 = {8b 45 0c 8b 4d 08 2b c8 83 e9 05 89 48 01 c6 00 e9 } //01 00 
		$a_01_2 = {8b 44 24 08 8b 4c 24 04 2b c8 83 e9 05 89 48 01 c6 00 e9 } //00 00 
	condition:
		any of ($a_*)
 
}