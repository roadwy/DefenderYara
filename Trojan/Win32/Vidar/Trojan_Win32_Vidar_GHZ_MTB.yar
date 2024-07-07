
rule Trojan_Win32_Vidar_GHZ_MTB{
	meta:
		description = "Trojan:Win32/Vidar.GHZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {b8 8a a5 08 00 c7 45 90 01 01 8d 00 00 00 c7 45 90 01 01 f0 d0 05 00 c7 45 90 01 01 01 14 00 00 c7 45 90 01 01 79 00 00 00 c7 45 90 01 01 15 00 00 00 b8 90 01 04 89 45 c0 6a 40 68 00 10 00 00 8b 45 f8 8b 10 ff 12 90 00 } //10
		$a_80_1 = {79 34 33 35 75 79 32 } //y435uy2  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}