
rule Trojan_Win32_Bublik_AP_MTB{
	meta:
		description = "Trojan:Win32/Bublik.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {bf 4e 3f 74 d2 57 2a 3d [0-04] 68 10 a7 38 08 00 2b 33 71 b5 87 33 68 7a 3a 47 b4 4e 87 4f a9 bb a1 e0 23 cf 02 3a e3 } //1
		$a_01_1 = {49 32 49 34 00 00 00 ed 94 f3 a7 d1 02 63 4a b3 90 21 98 bb 98 96 b5 74 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}