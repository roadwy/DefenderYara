
rule Trojan_Win32_SmokeLoader_O_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.O!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 55 fc 8b 45 d8 01 45 fc 8b 45 f4 8b 4d f8 8d 14 01 8b 4d f0 d3 e8 8b 4d fc 03 c3 33 c2 33 c8 89 4d fc 2b f1 8b 45 e0 29 45 f8 83 ef 01 0f 85 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}