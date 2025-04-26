
rule Virus_Win64_Expiro_AA_MTB{
	meta:
		description = "Virus:Win64/Expiro.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {50 51 52 53 55 56 57 41 50 41 51 41 52 41 53 41 54 41 55 41 56 41 57 55 48 8b ec 48 83 ec 20 48 83 e4 f0 48 8d 1d d6 39 f7 ff 48 ba 00 00 00 00 00 00 00 00 53 f7 93 90 02 00 00 81 b3 a0 02 00 00 e9 6d b2 28 f7 93 a4 03 00 00 f7 93 6c 03 00 00 81 83 d8 01 00 00 2a 39 44 7c f7 93 f8 00 00 00 81 43 14 6e 1b e8 5e } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}