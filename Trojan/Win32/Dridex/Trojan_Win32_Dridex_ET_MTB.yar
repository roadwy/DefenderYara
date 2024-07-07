
rule Trojan_Win32_Dridex_ET_MTB{
	meta:
		description = "Trojan:Win32/Dridex.ET!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 8b 4c 24 66 66 0b 4c 24 66 66 89 4c 24 66 66 8b 48 05 66 89 4c 24 5e 0f b7 44 24 5e 8b 54 24 28 } //10
		$a_01_1 = {8a 08 0f b6 c1 83 f8 6a 88 4c 24 2f 89 44 24 28 0f 84 d3 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}