
rule Trojan_Win32_Rhadamanthys_GA_MTB{
	meta:
		description = "Trojan:Win32/Rhadamanthys.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {ff 75 f8 ff 15 90 02 04 8d 45 f0 50 90 18 ff 25 30 90 01 01 42 00 90 00 } //01 00 
		$a_00_1 = {8b 9b a8 00 00 00 8d 4d 08 03 5e 08 51 ff 76 10 50 53 ff d7 } //01 00 
		$a_80_2 = {37 41 52 51 41 41 41 41 53 43 49 4a 41 51 41 45 41 41 41 42 49 41 49 42 41 } //7ARQAAAASCIJAQAEAAABIAIBA  00 00 
	condition:
		any of ($a_*)
 
}