
rule Trojan_Win32_Raccoon_AD_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {51 c7 04 24 02 00 00 00 8b 44 24 08 90 01 04 24 83 2c 24 02 8b 04 24 31 01 59 c2 04 00 } //10
		$a_01_1 = {c1 e8 05 05 12 c9 23 00 89 01 c3 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}
rule Trojan_Win32_Raccoon_AD_MTB_2{
	meta:
		description = "Trojan:Win32/Raccoon.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 0c 33 44 24 1c c7 05 ?? ?? ?? ?? 00 00 00 00 31 44 24 10 89 44 24 0c 8b 44 24 10 01 05 ?? ?? ?? ?? 8b 44 24 10 29 44 24 14 8b 54 24 14 c1 e2 04 89 54 24 0c 8b 44 24 ?? 01 44 24 0c 8b 44 24 14 03 44 24 20 } //1
		$a_03_1 = {8b 54 24 1c 31 54 24 0c c1 e9 05 03 [0-03] c7 05 ?? ?? ?? ?? b4 02 d7 cb c7 05 ?? ?? ?? ?? ff ff ff ff 89 4c 24 10 8b 44 24 10 31 44 24 0c 8b 44 24 0c 29 44 24 18 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}