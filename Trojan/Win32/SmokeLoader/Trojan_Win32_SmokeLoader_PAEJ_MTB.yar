
rule Trojan_Win32_SmokeLoader_PAEJ_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.PAEJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 44 24 18 8b c7 c1 e0 04 89 44 24 10 8b 44 24 28 01 44 24 10 8b 4c 24 14 8b c7 c1 e8 05 03 cf 89 44 24 18 8b 44 24 2c 01 44 24 18 8b 44 24 18 33 c1 31 44 24 10 8b 44 24 10 29 44 24 1c 8b 44 24 30 29 44 24 14 4b } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}