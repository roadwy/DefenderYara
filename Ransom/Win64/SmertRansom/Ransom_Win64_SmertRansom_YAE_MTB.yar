
rule Ransom_Win64_SmertRansom_YAE_MTB{
	meta:
		description = "Ransom:Win64/SmertRansom.YAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 63 c8 49 8b c7 48 f7 e1 48 c1 ea 05 48 8d 04 d2 48 c1 e0 02 48 2b c8 0f b6 44 0c 70 88 06 } //1
		$a_01_1 = {2d 2d 66 6f 6f 64 73 75 6d } //1 --foodsum
		$a_01_2 = {78 6d 62 2e 70 79 74 68 6f 6e 61 6e 79 77 68 65 72 65 2e 63 6f 6d } //1 xmb.pythonanywhere.com
		$a_01_3 = {2e 73 6d 65 72 74 } //1 .smert
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}