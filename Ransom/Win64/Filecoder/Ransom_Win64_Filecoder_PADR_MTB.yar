
rule Ransom_Win64_Filecoder_PADR_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.PADR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 ff c7 48 83 ff 04 75 07 48 c7 c7 00 00 00 00 8a 06 30 d8 88 06 48 ff c6 4c 39 ce 75 dc } //1
		$a_01_1 = {48 ff c6 88 17 48 ff c7 8a 16 01 db 75 0a 8b 1e 48 83 ee fc 11 db 8a 16 72 e6 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}