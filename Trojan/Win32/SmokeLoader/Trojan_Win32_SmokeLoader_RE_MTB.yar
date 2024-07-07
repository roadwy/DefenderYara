
rule Trojan_Win32_SmokeLoader_RE_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 ab 0f 1b 81 6c 24 90 01 01 8d 1f 25 59 81 ac 24 90 01 01 00 00 00 e0 02 53 2c 81 90 01 01 24 90 02 04 f0 b0 7d 6d 81 84 24 90 01 01 00 00 00 40 c1 58 20 81 44 24 90 01 01 f0 98 30 35 b8 8c 6d 49 02 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_SmokeLoader_RE_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 00 e1 34 ef c6 c3 29 08 c3 01 08 c3 } //1
		$a_03_1 = {36 dd 96 53 81 45 90 01 01 38 dd 96 53 8b 55 90 01 01 8b 4d 90 01 01 8b c2 d3 e0 90 02 40 8b c2 d3 e8 89 35 90 01 04 03 45 90 01 01 89 45 90 01 01 33 45 90 01 01 31 45 f8 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}