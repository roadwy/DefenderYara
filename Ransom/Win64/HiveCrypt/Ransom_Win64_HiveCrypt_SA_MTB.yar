
rule Ransom_Win64_HiveCrypt_SA_MTB{
	meta:
		description = "Ransom:Win64/HiveCrypt.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 92 c2 c0 e2 ?? 08 ca 8a 8c 04 ?? ?? ?? ?? 8d 59 ?? 80 fb ?? 0f 92 c3 c0 e3 ?? 08 cb 48 ?? ?? 38 da 74 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}