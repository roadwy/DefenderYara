
rule Trojan_Win32_Donut_ARA_MTB{
	meta:
		description = "Trojan:Win32/Donut.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {b8 81 80 80 80 f7 e1 c1 ea 07 02 d1 32 d1 80 f2 aa 88 14 31 41 81 f9 00 10 00 00 7c e3 } //2
		$a_01_1 = {2f 00 73 00 63 00 20 00 6f 00 6e 00 73 00 74 00 61 00 72 00 74 00 20 00 2f 00 72 00 6c 00 20 00 68 00 69 00 67 00 68 00 65 00 73 00 74 00 20 00 2f 00 66 00 20 00 2f 00 72 00 75 00 20 00 53 00 59 00 53 00 54 00 45 00 4d 00 } //2 /sc onstart /rl highest /f /ru SYSTEM
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}