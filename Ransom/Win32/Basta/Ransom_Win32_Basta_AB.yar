
rule Ransom_Win32_Basta_AB{
	meta:
		description = "Ransom:Win32/Basta.AB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //0a 00 
		$a_03_1 = {c7 45 f0 00 00 00 00 ff 75 10 83 ec 18 8b cc 89 65 10 ff 75 0c e8 90 01 04 c7 45 fc 01 00 00 00 ff 75 08 c6 45 fc 00 e8 90 01 04 83 c4 20 c7 45 fc 00 00 00 00 90 03 0d 0d 8b 4d f4 c7 45 f0 01 00 00 00 8b 45 08 c7 45 f0 01 00 00 00 8b 45 08 8b 4d f4 90 00 } //0a 00 
		$a_03_2 = {2b c2 d1 f8 83 f8 ff 0f 84 90 01 04 85 c0 0f 84 90 01 04 2b f0 83 fe 03 90 02 06 83 ff 08 8d 4d d4 68 90 01 04 0f 43 cb 83 c1 02 8d 34 41 56 e8 90 01 04 83 c4 08 85 c0 74 90 01 01 68 90 01 04 56 e8 90 01 04 83 c4 08 85 c0 74 90 01 01 68 90 01 04 56 e8 90 01 04 83 c4 08 85 c0 74 90 01 01 68 90 01 04 56 e8 90 01 04 83 c4 08 85 c0 74 90 00 } //00 00 
		$a_00_3 = {5d 04 00 00 e7 59 05 80 5c 3f 00 00 e8 59 05 80 00 00 01 00 } //04 00 
	condition:
		any of ($a_*)
 
}