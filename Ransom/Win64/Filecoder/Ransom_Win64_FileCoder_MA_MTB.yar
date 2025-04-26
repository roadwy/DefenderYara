
rule Ransom_Win64_FileCoder_MA_MTB{
	meta:
		description = "Ransom:Win64/FileCoder.MA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e8 7b dd fc ff e8 36 d1 fd ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Ransom_Win64_FileCoder_MA_MTB_2{
	meta:
		description = "Ransom:Win64/FileCoder.MA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8d 0c 51 48 8b 95 c0 00 00 00 48 d1 e2 48 2b ca 48 8b 54 c5 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}