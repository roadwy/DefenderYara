
rule Trojan_Win32_LummaStealer_NDO_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.NDO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {20 cb 20 c2 08 d3 89 ca 30 c1 20 c2 08 d1 89 ca 30 da 84 c9 } //2
		$a_01_1 = {89 d3 80 f3 01 88 df 89 d8 20 d7 08 f2 20 f8 30 df 80 f2 01 08 c7 88 f8 20 f7 80 f6 01 34 01 20 f0 30 de 08 f2 08 } //1
		$a_01_2 = {bf bd ef a9 a8 31 e0 89 44 24 54 8d 46 04 89 74 24 10 89 74 24 14 89 44 24 0c 89 44 24 18 8b 44 24 14 8b 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}