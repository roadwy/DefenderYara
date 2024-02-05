
rule Trojan_WinNT_Otlard_A{
	meta:
		description = "Trojan:WinNT/Otlard.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {6a 76 59 fe c5 0f 32 66 25 01 f0 48 66 81 38 4d 5a } //02 00 
		$a_01_1 = {c6 45 fb 3d c6 45 fc 00 c7 45 c8 31 00 00 00 } //01 00 
		$a_01_2 = {68 87 7e 34 c5 e8 } //01 00 
		$a_01_3 = {66 8b 11 81 fa ff 25 00 00 75 17 8b 45 f8 8b 48 02 } //01 00 
		$a_01_4 = {81 7d 08 ad de 01 c0 75 0a b8 ad de 01 c0 } //00 00 
	condition:
		any of ($a_*)
 
}