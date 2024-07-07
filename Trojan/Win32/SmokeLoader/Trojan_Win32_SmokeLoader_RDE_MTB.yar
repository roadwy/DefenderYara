
rule Trojan_Win32_SmokeLoader_RDE_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.RDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 44 24 1c 8b 44 24 1c 89 44 24 20 8b 4c 24 18 8b 54 24 14 d3 ea 8b cb } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}