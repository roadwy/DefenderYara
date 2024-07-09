
rule Trojan_Win32_SmokeLoader_AMBB_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.AMBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 f6 8b cf c1 e1 04 03 4c 24 2c 8b c7 c1 e8 05 03 44 24 38 8d 14 3b 33 ca } //1
		$a_03_1 = {89 74 24 1c 8b 44 24 30 01 44 24 1c 8b 44 24 14 33 44 24 1c 89 44 24 1c 8b 4c 24 1c 89 4c 24 1c 8b 44 24 1c 29 44 24 18 8b 54 24 18 c1 e2 04 89 54 24 14 8b 44 24 34 01 44 24 14 81 3d ?? ?? ?? ?? be 01 00 00 8b 44 24 18 8d 2c 03 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}