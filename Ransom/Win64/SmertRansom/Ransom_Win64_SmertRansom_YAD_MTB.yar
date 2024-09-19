
rule Ransom_Win64_SmertRansom_YAD_MTB{
	meta:
		description = "Ransom:Win64/SmertRansom.YAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2d 2d 66 6f 6f 64 73 75 6d } //1 --foodsum
		$a_01_1 = {2e 73 6d 65 72 74 } //1 .smert
		$a_01_2 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 Your files have been encrypted
		$a_01_3 = {53 74 61 72 74 20 61 6c 6c 20 6f 76 65 72 20 61 67 61 69 6e } //1 Start all over again
		$a_01_4 = {78 6d 62 2e 70 79 74 68 6f 6e 61 6e 79 77 68 65 72 65 2e 63 6f 6d } //1 xmb.pythonanywhere.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}