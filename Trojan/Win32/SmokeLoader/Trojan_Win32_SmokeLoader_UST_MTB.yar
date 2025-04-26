
rule Trojan_Win32_SmokeLoader_UST_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.UST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c1 c1 e0 04 03 44 24 30 8d 34 29 c1 e9 05 89 44 24 14 8b d9 83 fa 1b 75 ?? 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 44 24 14 03 5c 24 28 c7 05 ?? ?? ?? ?? 00 00 00 00 33 de 33 d8 2b fb 8b d7 c1 e2 04 89 54 24 14 8b 44 24 20 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}