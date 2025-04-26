
rule Ransom_Win64_Filecoder_PDT_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.PDT!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 00 10 00 00 } //1
		$a_01_1 = {48 ff c6 eb } //1
		$a_01_2 = {48 ff c7 eb } //1
		$a_01_3 = {48 ff c2 eb } //1
		$a_01_4 = {48 81 fa 3b 4a 00 00 eb } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}