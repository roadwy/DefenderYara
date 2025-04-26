
rule Ransom_Win64_MedusaLocker_A_MTB{
	meta:
		description = "Ransom:Win64/MedusaLocker.A!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {45 33 ff 45 33 c9 4c 89 7c 24 30 45 33 c0 c7 44 24 28 80 00 00 00 ba 00 00 00 c0 c7 44 24 20 01 00 00 00 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}