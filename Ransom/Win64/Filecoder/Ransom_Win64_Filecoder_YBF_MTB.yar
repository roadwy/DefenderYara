
rule Ransom_Win64_Filecoder_YBF_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.YBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {0f 57 c8 f3 0f 7f 48 ?? 66 0f 6f ca f3 0f 6f 40 ?? 0f 57 c2 f3 0f 7f 40 ?? f3 0f 6f } //1
		$a_01_1 = {80 30 3f 48 8d 40 01 ff c1 81 f9 2c 3c 00 00 72 } //1
		$a_00_2 = {47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 6c 00 6f 00 63 00 6b 00 76 00 37 00 } //1 Global\lockv7
		$a_00_3 = {6c 00 6f 00 63 00 6b 00 65 00 64 00 2e 00 68 00 74 00 6d 00 6c 00 } //1 locked.html
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}