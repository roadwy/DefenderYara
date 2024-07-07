
rule Ransom_Win64_Filecoder_PACR_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.PACR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b c2 48 8d 49 01 83 e0 07 48 ff c2 42 0f b6 04 08 30 41 ff 49 83 e8 01 75 e5 } //1
		$a_01_1 = {4d 61 6c 46 46 6c 65 52 } //1 MalFFleR
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}