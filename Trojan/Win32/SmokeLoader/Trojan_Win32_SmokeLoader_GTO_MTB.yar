
rule Trojan_Win32_SmokeLoader_GTO_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.GTO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c1 c1 e8 05 03 45 e0 c7 05 ?? ?? ?? ?? 19 36 6b ff 33 45 ?? 33 f8 89 7d f4 8b 45 f4 29 45 fc 89 75 f8 8b 45 d8 01 45 f8 2b 5d f8 ff 4d ec 89 5d e8 0f 85 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}