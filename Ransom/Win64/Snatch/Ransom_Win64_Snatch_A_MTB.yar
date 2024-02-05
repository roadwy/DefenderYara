
rule Ransom_Win64_Snatch_A_MTB{
	meta:
		description = "Ransom:Win64/Snatch.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 81 fb 00 08 00 00 0f 86 04 02 00 00 80 3d b6 13 31 00 01 75 11 89 f0 09 f8 a9 07 00 00 00 74 06 48 89 d9 f3 a4 c3 } //00 00 
	condition:
		any of ($a_*)
 
}