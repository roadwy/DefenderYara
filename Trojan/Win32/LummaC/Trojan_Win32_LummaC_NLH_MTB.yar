
rule Trojan_Win32_LummaC_NLH_MTB{
	meta:
		description = "Trojan:Win32/LummaC.NLH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 75 e8 0f be 34 1e 31 f0 8b 75 e8 0f af c7 43 39 da 75 ec } //2
		$a_01_1 = {89 d7 f7 df 31 f7 4a 21 f2 01 d2 29 fa 8d 34 09 83 e6 74 f7 de 01 ce 83 c6 7a 83 e6 7a } //1
		$a_01_2 = {01 f9 01 c2 89 ce 31 d6 f7 d1 21 d1 01 c9 29 f1 89 ca } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}