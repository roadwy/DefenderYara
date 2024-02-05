
rule Trojan_Win32_Spidser_A{
	meta:
		description = "Trojan:Win32/Spidser.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c4 20 89 04 8d e8 ba 00 10 8d 94 90 01 05 52 55 ff 15 90 01 04 85 c0 90 02 20 81 c4 44 02 00 00 90 00 } //01 00 
		$a_03_1 = {6a 01 55 55 55 89 04 8d e4 ba 00 10 68 90 01 04 41 55 55 89 0d 90 01 04 e8 90 01 04 8b 0d 90 01 04 8b 2d 90 01 04 8b 1d 90 01 04 83 c4 38 89 04 8d e4 ba 00 10 41 89 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}