
rule Trojan_Win32_LummaC_GTD_MTB{
	meta:
		description = "Trojan:Win32/LummaC.GTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {1d e9 b6 df 59 88 d8 8c 59 88 d8 8c 59 88 d8 8c 33 94 da 8c 70 88 d8 8c 59 88 d9 8c 5b 88 d8 8c eb 94 c8 8c 5b 88 d8 8c 59 88 d8 8c 56 88 d8 8c e1 8e de 8c 58 88 d8 8c 52 69 63 68 59 88 d8 8c } //5
		$a_01_1 = {5b f0 06 00 6f 00 00 00 00 e0 06 00 48 04 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}