
rule Virus_Win64_Expiro_DE_MTB{
	meta:
		description = "Virus:Win64/Expiro.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 83 ec 08 48 c7 04 24 00 00 00 00 48 83 c4 08 48 8b 4c 24 f8 48 c7 c2 a1 5a 00 00 49 c7 c0 00 30 00 00 49 c7 c1 40 00 00 00 ff d0 } //01 00 
		$a_01_1 = {54 d2 48 c7 c1 26 3e 00 00 41 b9 68 8d 00 00 41 ba 00 92 81 92 48 ff c9 44 30 0c 08 45 01 d1 41 d1 c1 48 85 c9 } //00 00 
	condition:
		any of ($a_*)
 
}