
rule Trojan_Win32_Zusy_MCF_MTB{
	meta:
		description = "Trojan:Win32/Zusy.MCF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 c2 d3 29 00 40 cf 27 00 2e d0 2d 00 4a cf 27 00 2e d0 23 00 43 cf 27 00 77 e9 2c 00 42 cf 27 00 77 e9 23 00 42 cf 27 00 41 cf 26 00 2c cf 27 00 a9 d0 2c 00 42 } //1
		$a_01_1 = {74 53 6e 61 63 75 6f 54 20 65 76 6f 6c 20 49 50 45 00 00 4c 01 04 00 f4 68 d2 50 } //1
		$a_01_2 = {40 00 00 40 2e 64 61 74 61 00 00 00 34 25 01 00 00 30 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}