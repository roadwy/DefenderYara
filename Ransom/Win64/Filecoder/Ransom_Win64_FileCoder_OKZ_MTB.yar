
rule Ransom_Win64_FileCoder_OKZ_MTB{
	meta:
		description = "Ransom:Win64/FileCoder.OKZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 0f b6 1c 13 45 31 d8 45 88 04 39 48 ff c7 4c 89 c8 4c 89 d2 66 90 48 39 f9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}