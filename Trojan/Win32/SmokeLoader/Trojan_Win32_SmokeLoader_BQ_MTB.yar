
rule Trojan_Win32_SmokeLoader_BQ_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.BQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b f0 8b c6 c1 e8 05 89 45 08 8d 45 08 50 c7 05 90 02 04 19 36 6b ff e8 90 02 04 8b 4d fc 8b c6 c1 e0 04 03 45 e8 03 ce 33 c1 33 45 08 2b f8 81 3d 90 02 04 93 00 00 00 74 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}