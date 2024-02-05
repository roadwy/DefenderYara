
rule Virus_Win64_Expiro_EN_bit{
	meta:
		description = "Virus:Win64/Expiro.EN!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {51 52 47 55 4a b9 60 00 00 00 00 00 00 00 65 4a 8b 11 56 4a 8b 72 10 4a 83 c2 18 4e 8b 2a 49 8b 55 10 41 57 4b 89 d5 4f 83 c5 30 49 8b 4d 00 4e 83 f9 00 74 2e 4e 8b 6a 60 4d 8b 7d 00 41 81 e7 df 00 df 00 4d 8b 6d 0c 45 c1 e5 08 45 01 fd 45 c1 e5 02 41 81 ed 2c cd 14 c9 4d 85 ed 0f 84 05 00 00 00 4a 8b 12 eb bc 8b 51 3c 48 83 c2 10 48 03 d1 46 8b 6a 78 4b 01 cd 43 56 45 8b 7d 20 4b 01 cf 45 8b 37 } //01 00 
		$a_03_1 = {e8 04 00 00 00 45 5f eb 29 46 8b 39 43 81 f7 90 01 04 44 89 3a 49 ff cd 4f ff cd 4f ff cd 4d ff cd 48 83 c2 04 4a 83 c1 04 45 85 ed 74 02 eb d8 90 00 } //01 00 
		$a_03_2 = {55 48 89 e5 41 55 41 56 41 57 48 83 ec 18 49 89 cf 49 c7 c6 02 00 00 00 48 c7 45 90 01 01 0c 00 00 00 48 c7 c0 0a 00 00 00 48 99 49 f7 fe 49 89 c3 48 c7 c0 1e 00 00 00 48 99 49 f7 fb 48 89 45 90 01 01 4d 89 dd 49 83 c5 03 4d 89 da 49 83 ea 03 49 c1 e2 02 4c 8b 4d 90 01 01 49 b8 90 01 08 4d 01 c1 47 89 0c 3a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}