
rule Ransom_Win64_Filecoder_PDT_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.PDT!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 00 10 00 00 } //01 00 
		$a_01_1 = {48 ff c6 eb } //01 00 
		$a_01_2 = {48 ff c7 eb } //01 00 
		$a_01_3 = {48 ff c2 eb } //01 00 
		$a_01_4 = {48 81 fa 3b 4a 00 00 eb } //00 00 
	condition:
		any of ($a_*)
 
}