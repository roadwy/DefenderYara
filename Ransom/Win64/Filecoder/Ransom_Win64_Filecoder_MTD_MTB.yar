
rule Ransom_Win64_Filecoder_MTD_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.MTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 01 d0 44 0f b6 00 48 8b 45 f8 48 8d 50 01 48 8b 45 10 48 01 d0 0f b6 08 48 8b 55 10 48 8b 45 f8 48 01 d0 44 89 c2 31 ca 88 10 48 83 45 ?? 01 48 8b 45 18 48 83 e8 01 48 39 45 f8 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}