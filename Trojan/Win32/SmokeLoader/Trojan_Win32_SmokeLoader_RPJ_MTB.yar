
rule Trojan_Win32_SmokeLoader_RPJ_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.RPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 28 8b d0 d3 e2 8b 4c 24 10 03 c8 c1 e8 05 03 d5 89 54 24 14 89 4c 24 1c 89 44 24 18 8b 44 24 3c 01 44 24 18 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}