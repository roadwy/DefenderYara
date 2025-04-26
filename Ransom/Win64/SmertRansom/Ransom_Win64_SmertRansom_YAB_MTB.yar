
rule Ransom_Win64_SmertRansom_YAB_MTB{
	meta:
		description = "Ransom:Win64/SmertRansom.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {48 63 c8 49 8b c7 48 f7 e1 48 c1 ea 05 48 8d 04 d2 48 c1 e0 02 48 2b c8 0f b6 44 0c 70 88 06 } //1
		$a_01_1 = {74 64 73 6f 70 65 72 61 74 69 6f 6e 61 6c 2e 70 79 74 68 6f 6e 61 6e 79 77 68 65 72 65 2e 63 6f 6d } //1 tdsoperational.pythonanywhere.com
		$a_01_2 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 2e 20 54 68 65 72 65 27 73 20 6e 6f 20 77 61 79 20 62 61 63 6b } //1 Your files have been encrypted. There's no way back
		$a_01_3 = {5c 52 45 41 44 4d 45 2e 74 78 74 } //1 \README.txt
		$a_01_4 = {2d 2d 66 6f 6f 64 73 75 6d } //1 --foodsum
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}