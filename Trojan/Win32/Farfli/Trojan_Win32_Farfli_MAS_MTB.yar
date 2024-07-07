
rule Trojan_Win32_Farfli_MAS_MTB{
	meta:
		description = "Trojan:Win32/Farfli.MAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f a2 8a da f6 d7 66 87 7c 24 03 8d 58 65 8d 64 24 08 eb 90 01 01 f8 66 89 5c 24 27 eb 90 00 } //5
		$a_03_1 = {91 2b db cc 5c 5c 9c 8a c7 07 02 90 01 05 00 00 00 8f 90 01 04 cc ab 66 e1 2f 90 00 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}