
rule Trojan_Win32_SmokeLoader_HIL_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.HIL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d6 d3 ea 03 d5 89 54 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 8b 44 24 90 01 01 8b 4c 24 90 01 01 50 51 8d 4c 24 90 01 01 e8 90 01 04 8b 44 24 90 01 01 89 44 24 90 01 01 8b 44 24 90 01 01 29 44 24 90 01 01 8b 44 24 90 01 01 89 44 24 90 01 01 81 44 24 90 01 05 83 ef 90 01 01 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}