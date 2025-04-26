
rule Trojan_Win32_Dridex_AF_MTB{
	meta:
		description = "Trojan:Win32/Dridex.AF!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b cf 0f af ce 8b c6 99 2b c2 8b 55 fc d1 f8 03 c8 8b 45 08 8a 04 02 2b cb 32 c1 } //10
		$a_01_1 = {33 c4 89 84 24 70 10 00 00 8b 45 08 53 56 33 db 57 33 ff } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}