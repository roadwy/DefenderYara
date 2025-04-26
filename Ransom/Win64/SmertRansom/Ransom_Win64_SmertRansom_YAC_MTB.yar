
rule Ransom_Win64_SmertRansom_YAC_MTB{
	meta:
		description = "Ransom:Win64/SmertRansom.YAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {78 6d 62 2e 70 79 74 68 6f 6e 61 6e 79 77 68 65 72 65 2e 63 6f 6d } //1 xmb.pythonanywhere.com
		$a_01_1 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 66 75 63 6b 65 64 } //1 Your files have been fucked
		$a_01_2 = {50 6c 61 79 20 63 68 65 73 73 20 61 67 61 69 6e 73 74 20 6d 65 2e 20 49 66 20 79 6f 75 20 77 69 6e 2c 20 79 6f 75 20 77 69 6c 6c 20 67 65 74 20 79 6f 75 72 20 66 69 6c 65 73 20 62 61 63 6b } //1 Play chess against me. If you win, you will get your files back
		$a_01_3 = {2d 2d 66 6f 6f 64 73 75 6d } //1 --foodsum
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}