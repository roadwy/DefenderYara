
rule Virus_Win64_Expiro_EK_MTB{
	meta:
		description = "Virus:Win64/Expiro.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {41 57 41 56 41 55 0f 84 eb 01 00 00 0f 85 e5 01 00 00 48 8d 44 24 38 48 89 44 24 28 48 89 7c 24 20 b9 02 01 00 00 48 89 f2 0f 84 ab 00 00 00 0f 85 a5 00 00 00 4c 89 f1 ff d0 48 81 c4 98 00 00 00 5b 5d 0f 84 c6 01 00 00 0f 85 c0 01 00 00 00 00 00 00 31 f6 4c 8d 64 24 36 66 0f 1f 44 00 00 41 8b 54 b5 00 48 01 fa 4c 89 e1 ff d5 74 47 75 45 } //00 00 
	condition:
		any of ($a_*)
 
}