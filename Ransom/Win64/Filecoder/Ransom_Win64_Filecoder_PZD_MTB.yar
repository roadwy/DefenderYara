
rule Ransom_Win64_Filecoder_PZD_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.PZD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 01 d0 0f b6 00 83 f0 55 89 c2 48 8d 4d ?? 48 8b 85 ?? 0f 00 00 48 01 c8 88 10 48 83 85 ?? 0f 00 00 01 48 8b 85 ?? 0f 00 00 48 3b 85 ?? 0f 00 00 72 } //3
		$a_02_1 = {66 69 6c 65 73 20 [0-32] 65 6e 63 72 79 70 74 65 64 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_02_1  & 1)*2) >=5
 
}