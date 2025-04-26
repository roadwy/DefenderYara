
rule Trojan_Win32_SmokeLoader_PBB_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.PBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {51 c7 04 24 ?? ?? ?? ?? 8b 44 24 08 83 2c 24 04 01 04 24 8b 04 24 31 01 59 } //1
		$a_03_1 = {8b 44 24 18 33 44 24 14 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 2b f8 8b cf c1 e1 04 } //1
		$a_01_2 = {8b 54 24 18 8b 44 24 14 33 d6 33 c2 2b d8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}