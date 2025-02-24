
rule Ransom_Win64_Lockbit_AUJ_MTB{
	meta:
		description = "Ransom:Win64/Lockbit.AUJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {65 48 8b 04 25 60 00 00 00 48 89 05 da b3 00 00 48 8b 40 18 48 8b 78 20 48 8b 07 48 8b 18 48 8d b4 24 e0 03 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}