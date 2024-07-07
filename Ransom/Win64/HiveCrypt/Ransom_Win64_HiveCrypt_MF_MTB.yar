
rule Ransom_Win64_HiveCrypt_MF_MTB{
	meta:
		description = "Ransom:Win64/HiveCrypt.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b7 44 08 04 35 5b 2e 00 00 40 80 f5 1a 40 0f b6 cd 88 8c 24 ee 05 00 00 48 c1 e1 30 48 c1 e0 20 48 09 c8 89 94 24 e8 05 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}