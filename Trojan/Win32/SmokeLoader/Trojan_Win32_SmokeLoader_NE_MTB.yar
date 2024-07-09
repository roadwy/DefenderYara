
rule Trojan_Win32_SmokeLoader_NE_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 45 0c 8b c6 c1 e8 05 89 45 08 8b 45 ec 01 45 08 8b 45 e8 83 25 ?? ?? ?? ?? ?? 03 f8 33 7d 08 33 7d 0c 89 7d 08 8b 45 08 01 05 ?? ?? ?? ?? 8b 45 08 29 45 fc 8b 4d fc c1 e1 04 03 4d f0 8b 45 fc 03 45 f8 89 45 0c 8b 55 fc } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}