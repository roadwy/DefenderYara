
rule Trojan_Win32_Zenpak_DC_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 1c 1e 8b 75 e4 32 1c 0e 8b 4d e8 8b 75 cc 88 1c 31 8b 4d f0 39 cf 8b 4d c4 89 4d dc 89 7d d8 89 55 d4 0f 84 } //2
		$a_01_1 = {8b 7d ec 8b 75 d0 8a 1c 37 8b 75 e4 32 1c 0e 8b 4d e8 8b 75 d0 88 1c 31 81 c6 01 00 00 00 8b 4d f0 39 ce 8b 4d cc 89 75 e0 89 4d dc 89 55 d8 0f 85 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}