
rule Trojan_Win32_SmokeLoader_PAEO_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.PAEO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 44 24 14 8b c3 c1 e0 04 89 44 24 10 8b 44 24 2c 01 44 24 10 8b c3 c1 e8 05 89 44 24 14 8b 44 24 30 01 44 24 14 8d 04 1e 33 44 24 14 31 44 24 10 8b 44 24 10 29 44 24 1c 8d 4c 24 18 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}