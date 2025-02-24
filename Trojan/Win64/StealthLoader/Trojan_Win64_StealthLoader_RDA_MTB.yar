
rule Trojan_Win64_StealthLoader_RDA_MTB{
	meta:
		description = "Trojan:Win64/StealthLoader.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {47 6c 6f 62 61 6c 5c 33 44 34 41 46 42 31 41 38 43 46 44 34 33 45 30 38 35 32 34 36 37 31 42 45 45 43 38 43 35 45 43 } //1 Global\3D4AFB1A8CFD43E08524671BEEC8C5EC
		$a_03_1 = {b9 04 00 00 00 41 8d ?? ?? ?? f3 a4 48 8b cb ff 15 } //2
		$a_01_2 = {4d 8b e0 45 8b f9 48 89 58 c8 48 89 58 d0 8b eb 89 58 08 ff 15 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2) >=5
 
}