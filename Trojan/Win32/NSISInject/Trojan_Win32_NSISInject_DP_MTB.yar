
rule Trojan_Win32_NSISInject_DP_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.DP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_03_0 = {81 f9 9a 13 00 00 74 90 01 01 fe c8 fe c8 fe c0 04 50 04 ed fe c8 fe c0 2c ce 2c 42 34 cd 04 9d 34 f1 34 25 fe c8 88 84 0d 90 01 04 83 c1 01 eb 90 00 } //1
		$a_03_1 = {81 f9 45 14 00 00 74 90 01 01 fe c0 04 8a 04 b7 fe c8 34 63 fe c8 2c 51 fe c0 2c 33 34 87 fe c0 88 84 0d 90 01 04 83 c1 01 eb 90 00 } //1
		$a_03_2 = {81 f9 78 12 00 00 74 90 01 01 2c 94 34 ef 2c 0d 2c 54 fe c8 04 4e 2c 4c 2c 77 fe c0 2c 40 88 84 0d 90 01 04 83 c1 01 eb 90 00 } //1
		$a_03_3 = {81 f9 e6 14 00 00 74 90 01 01 2c b3 34 ec fe c0 2c 17 fe c0 2c a4 04 2d 04 f3 34 a6 04 07 88 84 0d 90 01 04 83 c1 01 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=1
 
}