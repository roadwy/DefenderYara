
rule Ransom_Win64_FileCoder_MX_MTB{
	meta:
		description = "Ransom:Win64/FileCoder.MX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8d 05 cc a7 11 00 31 c9 31 ff 48 89 fe 0f 1f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Ransom_Win64_FileCoder_MX_MTB_2{
	meta:
		description = "Ransom:Win64/FileCoder.MX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 30 48 8b 5c 24 18 e8 27 ff ff ff e9 49 ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}