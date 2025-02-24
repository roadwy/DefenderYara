
rule Ransom_Win64_MedusaLocker_AMLK_MTB{
	meta:
		description = "Ransom:Win64/MedusaLocker.AMLK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 b8 02 00 00 00 48 8d 15 92 b2 06 00 48 8d 4c 24 50 e8 ?? ?? ?? ?? ?? 48 8d 44 24 50 48 83 7c 24 68 07 48 0f 47 44 24 50 66 01 38 48 8d 4c 24 50 48 83 7c 24 68 07 48 0f 47 4c 24 50 ff 15 } //2
		$a_01_1 = {48 8d 4c 24 50 48 83 7c 24 68 07 48 0f 47 4c 24 50 4c 8d 44 24 70 48 8d 55 80 ff 15 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}