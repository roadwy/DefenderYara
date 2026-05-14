
rule Ransom_Win64_Encoder_NB_MTB{
	meta:
		description = "Ransom:Win64/Encoder.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 05 11 4c 11 00 48 01 d8 44 8b 00 45 85 c0 74 0d 48 8b 50 10 48 8b 48 08 4d 89 e9 ff d7 } //2
		$a_01_1 = {8b 05 2e 4c 11 00 85 c0 0f 8e 51 fe ff ff 48 8b 3d 2b 66 11 00 31 db } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}