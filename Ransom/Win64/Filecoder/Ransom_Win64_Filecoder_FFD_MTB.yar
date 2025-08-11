
rule Ransom_Win64_Filecoder_FFD_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.FFD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 c0 c6 02 89 f0 44 30 e8 44 30 f0 48 8b 4d ?? 88 04 31 48 8d 46 01 48 89 45 f8 48 89 c6 48 39 c7 0f 84 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}