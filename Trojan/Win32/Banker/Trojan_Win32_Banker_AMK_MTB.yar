
rule Trojan_Win32_Banker_AMK_MTB{
	meta:
		description = "Trojan:Win32/Banker.AMK!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {88 44 24 01 80 44 24 01 95 8a 44 24 01 08 44 24 02 8a 44 24 03 30 44 24 02 fe 44 24 03 8a 44 24 02 88 04 0b } //10
		$a_01_1 = {8b 04 24 01 d8 69 c0 75 da 81 64 89 04 24 8b 04 24 01 d8 69 c0 75 da 81 64 89 04 24 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}