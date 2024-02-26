
rule Ransom_Win64_HiveCrypt_SU_MTB{
	meta:
		description = "Ransom:Win64/HiveCrypt.SU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 0f 7e c0 ff c0 89 47 90 01 01 4d 01 ef 31 c0 8a 4c 05 90 01 01 41 30 0c 07 48 8d 48 90 01 01 48 89 c8 49 39 cc 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}