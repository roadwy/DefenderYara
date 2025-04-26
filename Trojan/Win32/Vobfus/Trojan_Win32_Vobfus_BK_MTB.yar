
rule Trojan_Win32_Vobfus_BK_MTB{
	meta:
		description = "Trojan:Win32/Vobfus.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d fb fc fa a0 68 10 a7 38 08 00 2b 33 71 b5 60 48 3f 46 ee af 95 40 b5 87 84 e6 2f 2a 98 4e 2a 3d fb fc fa a0 68 10 a7 38 08 00 2b 33 71 } //1
		$a_01_1 = {39 dd 2b 93 53 64 91 21 3d fb fc fa a0 68 10 a7 38 08 00 2b 33 71 b5 43 6c 61 73 } //1
		$a_01_2 = {04 05 4c 91 e3 cf 5c b2 90 c3 d0 62 55 6d 33 a8 ef 2e 48 8c b3 c5 c0 fc 7a 7d } //1
		$a_01_3 = {3d fb fc fa a0 68 10 a7 38 08 00 2b 33 71 b5 22 3d fb fc fa a0 68 10 a7 38 08 00 2b 33 71 b5 02 00 00 00 0c 5d 40 00 1c 5d 40 00 00 00 00 00 79 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}