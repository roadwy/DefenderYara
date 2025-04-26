
rule Trojan_Win32_Lazy_EM_MTB{
	meta:
		description = "Trojan:Win32/Lazy.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {f6 da fe c2 66 3b eb f8 f6 d2 f8 32 da } //5
		$a_01_1 = {f6 da fe c2 66 0f 43 cc c0 cc 8e f6 d2 98 66 0f c9 66 b9 1d 10 d0 c2 f7 d8 66 0f a4 d0 94 c0 e4 47 32 da c0 e1 a1 66 85 da 66 8b 0c 14 81 ef 02 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=5
 
}