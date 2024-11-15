
rule Trojan_Win64_DriverLoader_ADRL_MTB{
	meta:
		description = "Trojan:Win64/DriverLoader.ADRL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f 57 c0 48 89 6c 24 30 48 03 fb c7 44 24 28 30 00 00 00 41 b9 30 00 00 00 48 89 6c 24 48 ba 48 20 00 80 48 89 6c 24 58 f3 0f 7f 44 24 64 48 8d 04 3e 89 6c 24 74 48 89 44 24 50 48 8d 44 24 48 48 89 44 24 20 c7 44 24 60 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}