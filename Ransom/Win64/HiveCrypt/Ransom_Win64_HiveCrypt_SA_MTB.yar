
rule Ransom_Win64_HiveCrypt_SA_MTB{
	meta:
		description = "Ransom:Win64/HiveCrypt.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f 92 c2 c0 e2 90 01 01 08 ca 8a 8c 04 90 01 04 8d 59 90 01 01 80 fb 90 01 01 0f 92 c3 c0 e3 90 01 01 08 cb 48 90 01 02 38 da 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}