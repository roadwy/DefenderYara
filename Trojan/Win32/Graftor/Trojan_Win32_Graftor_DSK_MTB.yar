
rule Trojan_Win32_Graftor_DSK_MTB{
	meta:
		description = "Trojan:Win32/Graftor.DSK!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a d3 80 e2 f0 8a c3 02 d2 24 fc 02 d2 08 54 24 12 c0 e0 04 08 44 24 11 81 3d a4 bf 46 00 c5 02 00 00 c7 05 a8 1c 44 00 50 d5 10 a8 } //2
		$a_01_1 = {8a 54 24 12 8a 44 24 11 88 14 2e 80 e3 c0 08 5c 24 13 88 44 2e 01 81 3d a4 bf 46 00 08 07 00 00 c7 05 98 bf 46 00 d6 26 f2 ce c7 05 9c bf 46 00 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}