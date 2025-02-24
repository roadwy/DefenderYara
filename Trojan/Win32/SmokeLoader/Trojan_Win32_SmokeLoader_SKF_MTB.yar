
rule Trojan_Win32_SmokeLoader_SKF_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.SKF!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d f0 03 4d f8 8b 45 f0 c1 e8 05 89 45 f4 8b 45 f4 03 45 d8 33 d9 33 c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}