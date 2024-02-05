
rule Trojan_Win32_SmokeLoader_REE_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.REE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {d3 e8 89 44 24 14 8b 44 24 30 01 44 24 14 8b 44 24 24 31 44 24 90 01 01 8b 4c 24 10 8b 54 24 90 01 01 51 52 8d 44 24 18 50 e8 90 01 04 8b 4c 24 10 8d 44 24 2c e8 90 01 04 81 c7 47 86 c8 61 83 ed 01 89 7c 24 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}