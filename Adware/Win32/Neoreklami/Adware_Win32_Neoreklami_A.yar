
rule Adware_Win32_Neoreklami_A{
	meta:
		description = "Adware:Win32/Neoreklami.A,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f0 8b 45 e0 8b 45 f8 8b 45 f8 8b 45 f8 8b 45 dc 8b 45 f4 89 5e 08 8b 4c 85 e8 8b 45 f4 89 4c 85 e8 33 c0 81 f9 a2 79 00 00 0f 9e c0 33 c9 85 c0 0f 9e c1 33 d2 81 f9 13 c0 00 00 89 4d d8 8b 45 f8 0f 94 c2 33 c9 3b d0 0f 9e c1 89 4d f8 89 5d f8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}