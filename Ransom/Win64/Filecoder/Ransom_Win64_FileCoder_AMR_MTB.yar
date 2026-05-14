
rule Ransom_Win64_FileCoder_AMR_MTB{
	meta:
		description = "Ransom:Win64/FileCoder.AMR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 8b 4c 1e 08 49 8b 54 1e 10 4d 8b 07 49 83 c0 10 4d 8b 0c 24 49 83 c1 10 48 89 7c 24 28 4c 89 6c 24 20 e8 ?? ?? ?? ?? 48 83 c3 20 48 39 de 75 cf } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}