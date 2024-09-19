
rule Trojan_Win32_BlackMoon_GMT_MTB{
	meta:
		description = "Trojan:Win32/BlackMoon.GMT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {51 d2 48 41 d1 de 30 c1 d7 b0 57 30 27 9f 49 12 fe bd 37 01 3d e5 28 00 00 54 92 24 ff 00 } //10
		$a_01_1 = {46 2d 40 41 26 70 77 64 3d } //1 F-@A&pwd=
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}