
rule Virus_Win64_Expiro_PABG_MTB{
	meta:
		description = "Virus:Win64/Expiro.PABG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {4e 8b 50 60 4d 8b 2a 45 81 e5 df 00 df 00 4f 8b 52 0c 41 c1 e2 08 45 01 ea 45 c1 ea 01 41 81 ea a5 99 22 19 4f 85 d2 0f 84 08 } //01 00 
		$a_01_1 = {45 8b 45 00 4f 03 c1 41 8b 40 0b 81 e8 65 63 74 00 83 f8 00 75 05 e9 06 00 00 00 49 83 c5 04 } //00 00 
	condition:
		any of ($a_*)
 
}