
rule Trojan_Win32_SmokeLoader_BZ_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.BZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 8b 4c 24 40 89 44 24 10 8d 44 24 10 e8 90 02 04 8b 44 24 30 31 44 24 14 8b 4c 24 10 31 4c 24 14 89 3d 90 02 04 8b 44 24 1c 89 44 24 2c 8b 44 24 14 29 44 24 2c 8b 44 24 2c 89 44 24 1c 8b 44 24 44 29 44 24 18 83 eb 01 0f 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}