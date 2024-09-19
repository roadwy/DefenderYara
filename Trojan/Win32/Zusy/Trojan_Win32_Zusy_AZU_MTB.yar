
rule Trojan_Win32_Zusy_AZU_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AZU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c2 c1 e8 18 89 4e 06 0f b6 0c 85 20 5d 5f 00 0f b6 46 0b 8b 0c 8d 20 51 5f 00 0f b6 04 85 20 5d 5f 00 33 0c 85 20 49 5f 00 0f b6 46 0c 0f b6 04 85 20 5d 5f 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zusy_AZU_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.AZU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 45 c4 c6 45 dc 4b c6 45 dd 45 c6 45 de 52 c6 45 df 4e c6 45 e0 45 c6 45 e1 4c c6 45 e2 33 c6 45 e3 32 c6 45 e4 2e c6 45 e5 64 c6 45 e6 6c c6 45 e7 6c 88 5d e8 ff d6 } //1
		$a_01_1 = {c6 45 cc 47 c6 45 cd 65 c6 45 ce 74 c6 45 cf 50 c6 45 d0 72 c6 45 d1 6f c6 45 d2 63 c6 45 d3 65 c6 45 d4 73 c6 45 d5 73 c6 45 d6 48 c6 45 d7 65 c6 45 d8 61 c6 45 d9 70 88 5d da ff d6 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}