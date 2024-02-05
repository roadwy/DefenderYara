
rule Ransom_Win32_Basta_AC{
	meta:
		description = "Ransom:Win32/Basta.AC,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //0a 00 
		$a_03_1 = {56 6a 00 6a 00 8b f1 56 68 90 01 04 6a 00 6a 00 ff 15 90 01 04 89 46 0c 5e c3 90 00 } //0a 00 
		$a_03_2 = {51 6a 10 e8 90 01 04 83 c4 04 89 45 90 01 01 90 02 07 85 c0 74 90 01 01 8b 4d 08 89 48 08 8b 4d 0c 89 48 04 8b 4d 10 89 08 90 00 } //00 00 
		$a_00_3 = {5d 04 00 00 0a 62 05 80 5c 26 00 00 0d 62 05 80 00 00 01 00 } //08 00 
	condition:
		any of ($a_*)
 
}