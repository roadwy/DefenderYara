
rule Trojan_Win32_Zusy_ARA_MTB{
	meta:
		description = "Trojan:Win32/Zusy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 0f 8a c1 32 c4 8a e1 88 07 47 43 3b de 72 f0 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Zusy_ARA_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c8 31 d2 f7 f6 8b 47 28 0f b6 04 10 30 04 0b 83 c1 01 39 cd 75 e9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Zusy_ARA_MTB_3{
	meta:
		description = "Trojan:Win32/Zusy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 81 80 80 80 f7 e1 c1 ea 07 02 d1 30 91 ?? ?? ?? ?? 41 81 f9 eb d5 06 00 72 e5 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Zusy_ARA_MTB_4{
	meta:
		description = "Trojan:Win32/Zusy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {32 d1 41 81 e1 ff 00 00 80 88 94 05 60 fd ff ff 79 08 49 81 c9 00 ff ff ff 41 40 83 f8 ?? 7c da } //2
		$a_01_1 = {8a 84 0f 74 24 a6 b2 32 c2 42 81 e2 ff 00 00 80 88 04 31 79 08 4a 81 ca 00 ff ff ff 42 41 83 f9 0e 7c dd } //2
		$a_80_2 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //InternetReadFile  1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_80_2  & 1)*1) >=3
 
}