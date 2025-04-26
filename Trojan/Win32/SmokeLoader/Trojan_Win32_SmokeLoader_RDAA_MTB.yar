
rule Trojan_Win32_SmokeLoader_RDAA_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.RDAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 44 24 10 2b e8 89 44 24 14 8b c5 c1 e0 04 89 44 24 10 8b 44 24 2c 01 44 24 10 8b c5 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}