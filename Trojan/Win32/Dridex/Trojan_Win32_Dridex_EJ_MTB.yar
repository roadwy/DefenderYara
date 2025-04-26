
rule Trojan_Win32_Dridex_EJ_MTB{
	meta:
		description = "Trojan:Win32/Dridex.EJ!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 c1 8d 44 10 f8 8b 54 24 10 8b 32 8a d3 2a d1 80 c2 7b } //10
		$a_01_1 = {8b 4c 24 10 8b d7 2b d3 81 ea 85 69 00 00 0f b7 da 81 c6 48 92 03 01 0f b7 d3 89 31 83 c1 04 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}