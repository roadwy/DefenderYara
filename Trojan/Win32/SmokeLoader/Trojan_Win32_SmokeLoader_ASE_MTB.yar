
rule Trojan_Win32_SmokeLoader_ASE_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.ASE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 ea 8b 4c 24 90 01 01 03 c7 89 44 24 90 01 01 8d 44 24 28 89 54 24 28 c7 05 90 01 08 e8 90 01 04 8b 44 24 24 31 44 24 10 81 3d 90 01 08 75 90 01 01 68 90 01 04 53 53 ff 15 90 01 04 8b 44 24 10 31 44 24 28 8b 44 24 28 83 44 24 18 90 01 01 29 44 24 18 83 6c 24 18 90 01 01 8b 44 24 18 8d 4c 24 90 01 01 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}