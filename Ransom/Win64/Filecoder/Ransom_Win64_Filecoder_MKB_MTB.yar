
rule Ransom_Win64_Filecoder_MKB_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.MKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {65 48 8b 04 25 30 00 00 00 48 8b 40 60 48 8b 40 18 4c 89 c6 4d 89 c8 66 48 0f 6e c9 48 89 d1 48 8b 40 20 48 8b 28 } //1
		$a_01_1 = {61 6c 6c 20 66 69 6c 65 73 20 63 72 79 70 74 65 64 2c 20 65 78 69 74 90 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}