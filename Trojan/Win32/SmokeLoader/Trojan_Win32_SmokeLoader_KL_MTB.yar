
rule Trojan_Win32_SmokeLoader_KL_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.KL!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {d3 e8 03 45 d0 89 45 fc 8b 45 f4 31 45 f8 8b 45 f8 33 45 fc 83 25 0c e7 42 00 00 81 45 e8 47 86 c8 61 2b d8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}