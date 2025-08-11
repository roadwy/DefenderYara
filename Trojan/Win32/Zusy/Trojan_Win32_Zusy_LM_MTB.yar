
rule Trojan_Win32_Zusy_LM_MTB{
	meta:
		description = "Trojan:Win32/Zusy.LM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {03 c5 81 c0 4c 00 00 00 b9 da 05 00 00 ba 85 3c de 9f 30 10 40 49 } //2
		$a_01_1 = {b0 c0 bc 40 0b b0 c0 bc 8b 00 97 37 37 37 34 c9 ba 69 37 a1 bc 47 0b a1 bc b3 07 03 37 37 37 1c ef bc 60 37 b0 ce bc 4e 33 b0 ce } //1
		$a_01_2 = {00 dc 02 00 00 00 06 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 00 00 00 00 00 00 00 00 00 80 00 00 00 30 15 00 00 66 00 00 00 dc 08 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}
rule Trojan_Win32_Zusy_LM_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.LM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 55 f0 8b 45 f4 01 d0 0f b6 00 89 c2 8b 45 e8 89 d1 31 c1 8b 55 f0 8b 45 f4 01 d0 89 ca 88 10 } //2
		$a_01_1 = {8b 55 d8 89 d0 c1 e0 02 01 d0 c1 e0 03 89 c2 8b 45 c8 01 d0 8b 40 08 8d 95 7c ff ff ff 89 54 24 0c 8b 55 d4 89 54 24 08 89 44 24 04 8b 45 a4 89 04 24 a1 74 20 40 00 ff d0 83 ec 10 } //1
		$a_03_2 = {8b 55 f0 89 d0 c1 e0 02 01 d0 c1 e0 03 89 c2 8b 45 e0 01 d0 89 c2 8d 45 d4 89 44 24 04 89 14 24 e8 ?? ?? ?? ?? 85 c0 75 ?? 8b 55 f0 89 d0 c1 e0 02 01 d0 c1 e0 03 89 c2 8b 45 e0 01 d0 8b 50 0c 8b 45 ec 01 d0 89 45 f4 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=4
 
}